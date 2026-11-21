import { NextResponse } from "next/server";
import { getDatabase, saveDatabase, Schedule } from "../jobs_store";
import crypto from "crypto";

// GET: List all schedules
export async function GET() {
  try {
    const db = getDatabase();
    return NextResponse.json({ schedules: db.schedules || [] });
  } catch (error: any) {
    return NextResponse.json({ error: error.message }, { status: 500 });
  }
}

// POST: Add or update a schedule
export async function POST(request: Request) {
  try {
    const body = await request.json();
    const { id, name, targetId, tests, frequency } = body;

    if (!name || !targetId || !frequency || !tests) {
      return NextResponse.json({ error: "Missing required fields" }, { status: 400 });
    }

    const db = getDatabase();
    if (!db.schedules) db.schedules = [];

    let schedule: Schedule | undefined;
    if (id) {
      schedule = db.schedules.find(s => s.id === id);
    }

    // Calculate next run
    const next = new Date();
    if (frequency === "daily") {
      next.setDate(next.getDate() + 1);
    } else if (frequency === "weekly") {
      next.setDate(next.getDate() + 7);
    } else if (frequency === "monthly") {
      next.setDate(next.getDate() + 30);
    }

    if (schedule) {
      // Update
      schedule.name = name;
      schedule.targetId = targetId;
      schedule.tests = tests;
      schedule.frequency = frequency;
      schedule.nextRun = next.toISOString();
    } else {
      // Add
      const newSchedule: Schedule = {
        id: id || "schedule-" + crypto.randomUUID().substring(0, 8),
        name,
        targetId,
        tests,
        frequency,
        nextRun: next.toISOString(),
        created_at: new Date().toISOString()
      };
      db.schedules.push(newSchedule);
    }

    saveDatabase(db);
    return NextResponse.json({ success: true, schedules: db.schedules });
  } catch (error: any) {
    return NextResponse.json({ error: error.message }, { status: 500 });
  }
}

// DELETE: Remove a schedule
export async function DELETE(request: Request) {
  try {
    const { searchParams } = new URL(request.url);
    const id = searchParams.get("id");

    if (!id) {
      return NextResponse.json({ error: "Missing schedule ID" }, { status: 400 });
    }

    const db = getDatabase();
    if (!db.schedules) db.schedules = [];

    db.schedules = db.schedules.filter(s => s.id !== id);
    saveDatabase(db);

    return NextResponse.json({ success: true, schedules: db.schedules });
  } catch (error: any) {
    return NextResponse.json({ error: error.message }, { status: 500 });
  }
}
