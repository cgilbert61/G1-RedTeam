import fs from "fs";
import path from "path";
import AdmZip from "adm-zip";
import crypto from "crypto";
import { NextResponse } from "next/server";
import { getDatabase, saveDatabase } from "../../jobs_store";

export async function POST() {
  try {
    const downloadsDirs = [
      "/downloads",
      "C:/Users/chuck/Downloads",
      path.join(process.env.HOME || "", "Downloads")
    ];

    let downloadsDir = "";
    for (const d of downloadsDirs) {
      if (fs.existsSync(d)) {
        downloadsDir = d;
        break;
      }
    }

    if (!downloadsDir) {
      return NextResponse.json({
        error: `Downloads folder not found inside container or on host. Checked: ${JSON.stringify(downloadsDirs)}`
      }, { status: 404 });
    }

    // Find all files matching g1163rt_g3_bundle_latest*.zip or T012613_20260825.zip
    const files = fs.readdirSync(downloadsDir);
    const zipFiles = files
      .filter(f => (f.startsWith("g1163rt_g3_bundle_latest") || /^T\d{6}_\d{8}\.zip$/.test(f)) && f.endsWith(".zip"))
      .map(f => {
        const fullPath = path.join(downloadsDir, f);
        const stat = fs.statSync(fullPath);
        return { name: f, fullPath, mtime: stat.mtimeMs };
      });

    if (zipFiles.length === 0) {
      return NextResponse.json({
        error: `No threat bundle zip files found in '${downloadsDir}' matching 'g1163rt_g3_bundle_latest*.zip' or 'T*.zip'.`
      }, { status: 404 });
    }

    // Pick the most recent zip file
    const latestZip = zipFiles.sort((a, b) => b.mtime - a.mtime)[0];

    // Read ZIP using adm-zip
    const zip = new AdmZip(latestZip.fullPath);
    const zipEntries = zip.getEntries();
    const uniquePrompts = new Set<string>();

    const promptsEntry = zipEntries.find(entry => entry.entryName === "prompts.json");
    const manifestEntry = zipEntries.find(entry => entry.entryName === "manifest.json");

    if (promptsEntry) {
      const promptsContent = promptsEntry.getData().toString("utf8");
      const promptsData = JSON.parse(promptsContent);
      const rawItems = promptsData.prompts || [];

      if (Array.isArray(rawItems)) {
        for (const item of rawItems) {
          const orig = item.original_prompt || item.prompt;
          if (orig && typeof orig === "string") {
            uniquePrompts.add(orig.trim());
          }
          
          const semanticVars = item.synthetic_variations?.semantic || [];
          if (Array.isArray(semanticVars)) {
            for (const v of semanticVars) {
              if (v && typeof v === "string") {
                uniquePrompts.add(v.trim());
              }
            }
          }

          const obfuscatedVars = item.synthetic_variations?.obfuscated || [];
          if (Array.isArray(obfuscatedVars)) {
            for (const v of obfuscatedVars) {
              if (v && typeof v === "string") {
                uniquePrompts.add(v.trim());
              }
            }
          }
        }
      }
    } else if (manifestEntry) {
      try {
        const manifestContent = manifestEntry.getData().toString("utf8");
        const manifestData = JSON.parse(manifestContent);
        const signatures = manifestData.signatures || {};
        for (const sigId of Object.keys(signatures)) {
          const sig = signatures[sigId];
          const prompt = sig.vector_payload?.metadata?.canonical_text_truncated || sig.vector_payload?.metadata?.canonical_text;
          if (prompt && typeof prompt === "string") {
            uniquePrompts.add(prompt.trim());
          }
        }
      } catch (e) {
        console.error("Failed to parse manifest.json", e);
      }
    } else {
      // Fallback: search in vectors folder
      for (const entry of zipEntries) {
        if (entry.entryName.startsWith("vectors/") && entry.entryName.endsWith(".json")) {
          try {
            const fileContent = entry.getData().toString("utf8");
            const fileData = JSON.parse(fileContent);
            const prompt = fileData.metadata?.canonical_text_truncated || fileData.metadata?.canonical_text;
            if (prompt && typeof prompt === "string") {
              uniquePrompts.add(prompt.trim());
            }
          } catch (e) {}
        }
      }
    }

    if (uniquePrompts.size === 0) {
      return NextResponse.json({
        error: "Incompatible bundle zip file: No prompts or threat vectors could be parsed."
      }, { status: 400 });
    }

    const promptsArray = Array.from(uniquePrompts).filter(p => p);

    if (promptsArray.length === 0) {
      return NextResponse.json({
        error: "No prompt strings could be parsed from the bundle."
      }, { status: 400 });
    }

    const datasetName = latestZip.name.replace(/\.zip$/, "");
    const db = getDatabase();
    if (!db.datasets) db.datasets = [];

    let dataset = db.datasets.find(d => d.name === datasetName);
    if (dataset) {
      dataset.prompts = promptsArray;
    } else {
      dataset = {
        id: "dataset-" + crypto.randomUUID().substring(0, 8),
        name: datasetName,
        prompts: promptsArray
      };
      db.datasets.push(dataset);
    }

    saveDatabase(db);

    return NextResponse.json({
      success: true,
      imported_from: latestZip.name,
      count: promptsArray.length
    });
  } catch (error: any) {
    console.error("Error importing threat bundle zip:", error);
    return NextResponse.json({ error: error.message }, { status: 500 });
  }
}
