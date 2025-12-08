"""
Message storage helper using aiosqlite for async access.

Provides MessageStore with methods to save messages, fetch undelivered
messages, mark delivered and fetch history.
"""
from __future__ import annotations

import aiosqlite
import datetime
from typing import List, Optional, Dict, Any

DEFAULT_DB = "messages.db"


class MessageStore:
    def __init__(self, db_path: str = DEFAULT_DB):
        self.db_path = db_path

    async def init_db(self) -> None:
        async with aiosqlite.connect(self.db_path) as db:
            await db.execute(
                """
                CREATE TABLE IF NOT EXISTS messages (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    sender TEXT NOT NULL,
                    recipient TEXT NOT NULL,
                    content TEXT NOT NULL,
                    timestamp TEXT NOT NULL,
                    delivered INTEGER NOT NULL DEFAULT 0
                )
                """
            )
            await db.commit()

    async def save_message(self, sender: str, recipient: str, content: str) -> int:
        ts = datetime.datetime.utcnow().isoformat() + "Z"
        async with aiosqlite.connect(self.db_path) as db:
            cur = await db.execute(
                "INSERT INTO messages (sender, recipient, content, timestamp, delivered) VALUES (?, ?, ?, ?, 0)",
                (sender, recipient, content, ts),
            )
            await db.commit()
            return cur.lastrowid

    async def get_undelivered(self, username: str) -> List[Dict[str, Any]]:
        async with aiosqlite.connect(self.db_path) as db:
            db.row_factory = aiosqlite.Row
            cur = await db.execute("SELECT * FROM messages WHERE recipient = ? AND delivered = 0 ORDER BY id ASC", (username,))
            rows = await cur.fetchall()
            return [dict(r) for r in rows]

    async def mark_delivered(self, message_id: int) -> None:
        async with aiosqlite.connect(self.db_path) as db:
            await db.execute("UPDATE messages SET delivered = 1 WHERE id = ?", (message_id,))
            await db.commit()

    async def get_history(self, user_a: str, user_b: Optional[str] = None, limit: int = 100) -> List[Dict[str, Any]]:
        async with aiosqlite.connect(self.db_path) as db:
            db.row_factory = aiosqlite.Row
            if user_b:
                cur = await db.execute(
                    "SELECT * FROM messages WHERE (sender = ? AND recipient = ?) OR (sender = ? AND recipient = ?) ORDER BY id DESC LIMIT ?",
                    (user_a, user_b, user_b, user_a, limit),
                )
            else:
                cur = await db.execute(
                    "SELECT * FROM messages WHERE sender = ? OR recipient = ? ORDER BY id DESC LIMIT ?",
                    (user_a, user_a, limit),
                )
            rows = await cur.fetchall()
            # return in chronological order
            return [dict(r) for r in reversed(rows)]
