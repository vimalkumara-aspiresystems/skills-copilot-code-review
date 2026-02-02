"""
MongoDB database configuration and setup for Mergington High School API
"""

import os
import copy
from typing import Any, Dict, Iterable, List

from pymongo import MongoClient
from pymongo.errors import ServerSelectionTimeoutError, ConnectionFailure
from argon2 import PasswordHasher, exceptions as argon2_exceptions


class UpdateResult:
    def __init__(self, modified_count: int):
        self.modified_count = modified_count


class InMemoryCollection:
    def __init__(self) -> None:
        self._docs: Dict[Any, Dict[str, Any]] = {}

    def count_documents(self, query: Dict[str, Any]) -> int:
        return sum(1 for _ in self.find(query))

    def insert_one(self, doc: Dict[str, Any]) -> None:
        doc_id = doc.get("_id")
        if doc_id is None:
            raise ValueError("Document must include _id")
        self._docs[doc_id] = copy.deepcopy(doc)

    def find(self, query: Dict[str, Any]) -> Iterable[Dict[str, Any]]:
        for doc in self._docs.values():
            if self._matches_query(doc, query):
                yield copy.deepcopy(doc)

    def find_one(self, query: Dict[str, Any]) -> Dict[str, Any] | None:
        """Return the first document matching the query.

        The loop short-circuits via `return` on the first match; it does not
        continue iterating over remaining documents.
        """
        for doc in self._docs.values():
            if self._matches_query(doc, query):
                return copy.deepcopy(doc)
        return None

    def update_one(self, query: Dict[str, Any], update: Dict[str, Any]) -> UpdateResult:
        for doc_id, doc in self._docs.items():
            if self._matches_query(doc, query):
                modified = self._apply_update(doc, update)
                if modified:
                    self._docs[doc_id] = doc
                return UpdateResult(1 if modified else 0)
        return UpdateResult(0)

    def aggregate(self, pipeline: List[Dict[str, Any]]) -> Iterable[Dict[str, Any]]:
        docs = list(self._docs.values())
        for stage in pipeline:
            if "$unwind" in stage:
                path = stage["$unwind"].lstrip("$")
                docs = self._unwind(docs, path)
            elif "$group" in stage:
                group_id = stage["$group"].get("_id", "")
                path = group_id.lstrip("$")
                docs = self._group_by(docs, path)
            elif "$sort" in stage:
                sort_spec = stage["$sort"]
                docs = self._sort_docs(docs, sort_spec)
            else:
                raise NotImplementedError("Unsupported aggregation stage")
        for doc in docs:
            yield copy.deepcopy(doc)

    def _unwind(self, docs: List[Dict[str, Any]], path: str) -> List[Dict[str, Any]]:
        unwound: List[Dict[str, Any]] = []
        for doc in docs:
            value = self._get_nested_value(doc, path)
            if isinstance(value, list):
                for item in value:
                    new_doc = copy.deepcopy(doc)
                    self._set_nested_value(new_doc, path, item)
                    unwound.append(new_doc)
            else:
                unwound.append(copy.deepcopy(doc))
        return unwound

    def _group_by(self, docs: List[Dict[str, Any]], path: str) -> List[Dict[str, Any]]:
        grouped: Dict[Any, Dict[str, Any]] = {}
        for doc in docs:
            key = self._get_nested_value(doc, path)
            if key not in grouped:
                grouped[key] = {"_id": key}
        return list(grouped.values())

        return sorted(
            docs,
            key=lambda d: (d.get(key) is None, d.get(key, "")),
            reverse=reverse,
        )
        if not sort_spec:
            return docs
        key, direction = next(iter(sort_spec.items()))
        reverse = direction < 0
        return sorted(docs, key=lambda d: d.get(key), reverse=reverse)

    def _matches_query(self, doc: Dict[str, Any], query: Dict[str, Any]) -> bool:
        for key, criteria in query.items():
            value = self._get_nested_value(doc, key)
            if not self._matches_criteria(value, criteria):
                return False
        return True

    def _matches_criteria(self, value: Any, criteria: Any) -> bool:
        if isinstance(criteria, dict):
            if "$in" in criteria:
                options = criteria["$in"]
                if isinstance(value, list):
                    return any(item in options for item in value)
                return value in options
            if "$gte" in criteria:
                if value is None or value < criteria["$gte"]:
                    return False
            if "$lte" in criteria:
                if value is None or value > criteria["$lte"]:
                    return False
            return True
        return value == criteria

    def _apply_update(self, doc: Dict[str, Any], update: Dict[str, Any]) -> bool:
        modified = False
        if "$push" in update:
            for field, value in update["$push"].items():
                existing = self._get_nested_value(doc, field)
                if existing is None:
                    existing = []
                    self._set_nested_value(doc, field, existing)
                if isinstance(existing, list):
                    existing.append(value)
                    modified = True
        if "$pull" in update:
            for field, value in update["$pull"].items():
                existing = self._get_nested_value(doc, field)
                if isinstance(existing, list):
                    original_len = len(existing)
                    existing[:] = [item for item in existing if item != value]
                    if len(existing) != original_len:
                        modified = True
        return modified

    def _get_nested_value(self, doc: Dict[str, Any], path: str) -> Any:
        parts = path.split(".")
        current: Any = doc
        for part in parts:
            if not isinstance(current, dict) or part not in current:
                return None
            current = current[part]
        return current

    def _set_nested_value(self, doc: Dict[str, Any], path: str, value: Any) -> None:
        parts = path.split(".")
        current = doc
        for part in parts[:-1]:
            if part not in current or not isinstance(current[part], dict):
                current[part] = {}
            current = current[part]
        current[parts[-1]] = value


def _connect_mongo() -> tuple[Any, Any] | None:
    mongo_uri = os.getenv("MONGODB_URI", "mongodb://localhost:27017/")
    try:
        client = MongoClient(
            mongo_uri,
            serverSelectionTimeoutMS=2000,
            connectTimeoutMS=2000,
            socketTimeoutMS=2000,
        )
        client.admin.command("ping")
        db = client["mergington_high"]
        return db["activities"], db["teachers"]
    except (ServerSelectionTimeoutError, ConnectionFailure, OSError):
        return None


def _init_collections() -> tuple[Any, Any]:
    connected = _connect_mongo()
    if connected:
        return connected
    return InMemoryCollection(), InMemoryCollection()


# Connect to MongoDB (or fallback to in-memory collections)
activities_collection, teachers_collection = _init_collections()

# Methods


def hash_password(password):
    """Hash password using Argon2"""
    ph = PasswordHasher()
    return ph.hash(password)


def verify_password(hashed_password: str, plain_password: str) -> bool:
    """Verify a plain password against an Argon2 hashed password.

    Returns True when the password matches, False otherwise.
    """
    ph = PasswordHasher()
    try:
        ph.verify(hashed_password, plain_password)
        return True
    except argon2_exceptions.VerifyMismatchError:
        return False
    except Exception:
        # For any other exception (e.g., invalid hash), treat as non-match
        return False


def init_database():
    """Initialize database if empty"""

    # Initialize activities if empty
    if activities_collection.count_documents({}) == 0:
        for name, details in initial_activities.items():
            activities_collection.insert_one({"_id": name, **details})

    # Initialize teacher accounts if empty
    if teachers_collection.count_documents({}) == 0:
        for teacher in initial_teachers:
            teachers_collection.insert_one(
                {"_id": teacher["username"], **teacher})


# Initial database if empty
initial_activities = {
    "Chess Club": {
        "description": "Learn strategies and compete in chess tournaments",
        "schedule": "Mondays and Fridays, 3:15 PM - 4:45 PM",
        "schedule_details": {
            "days": ["Monday", "Friday"],
            "start_time": "15:15",
            "end_time": "16:45"
        },
        "max_participants": 12,
        "participants": ["michael@mergington.edu", "daniel@mergington.edu"]
    },
    "Programming Class": {
        "description": "Learn programming fundamentals and build software projects",
        "schedule": "Tuesdays and Thursdays, 7:00 AM - 8:00 AM",
        "schedule_details": {
            "days": ["Tuesday", "Thursday"],
            "start_time": "07:00",
            "end_time": "08:00"
        },
        "max_participants": 20,
        "participants": ["emma@mergington.edu", "sophia@mergington.edu"]
    },
    "Morning Fitness": {
        "description": "Early morning physical training and exercises",
        "schedule": "Mondays, Wednesdays, Fridays, 6:30 AM - 7:45 AM",
        "schedule_details": {
            "days": ["Monday", "Wednesday", "Friday"],
            "start_time": "06:30",
            "end_time": "07:45"
        },
        "max_participants": 30,
        "participants": ["john@mergington.edu", "olivia@mergington.edu"]
    },
    "Soccer Team": {
        "description": "Join the school soccer team and compete in matches",
        "schedule": "Tuesdays and Thursdays, 3:30 PM - 5:30 PM",
        "schedule_details": {
            "days": ["Tuesday", "Thursday"],
            "start_time": "15:30",
            "end_time": "17:30"
        },
        "max_participants": 22,
        "participants": ["liam@mergington.edu", "noah@mergington.edu"]
    },
    "Basketball Team": {
        "description": "Practice and compete in basketball tournaments",
        "schedule": "Wednesdays and Fridays, 3:15 PM - 5:00 PM",
        "schedule_details": {
            "days": ["Wednesday", "Friday"],
            "start_time": "15:15",
            "end_time": "17:00"
        },
        "max_participants": 15,
        "participants": ["ava@mergington.edu", "mia@mergington.edu"]
    },
    "Art Club": {
        "description": "Explore various art techniques and create masterpieces",
        "schedule": "Thursdays, 3:15 PM - 5:00 PM",
        "schedule_details": {
            "days": ["Thursday"],
            "start_time": "15:15",
            "end_time": "17:00"
        },
        "max_participants": 15,
        "participants": ["amelia@mergington.edu", "harper@mergington.edu"]
    },
    "Drama Club": {
        "description": "Act, direct, and produce plays and performances",
        "schedule": "Mondays and Wednesdays, 3:30 PM - 5:30 PM",
        "schedule_details": {
            "days": ["Monday", "Wednesday"],
            "start_time": "15:30",
            "end_time": "17:30"
        },
        "max_participants": 20,
        "participants": ["ella@mergington.edu", "scarlett@mergington.edu"]
    },
    "Math Club": {
        "description": "Solve challenging problems and prepare for math competitions",
        "schedule": "Tuesdays, 7:15 AM - 8:00 AM",
        "schedule_details": {
            "days": ["Tuesday"],
            "start_time": "07:15",
            "end_time": "08:00"
        },
        "max_participants": 10,
        "participants": ["james@mergington.edu", "benjamin@mergington.edu"]
    },
    "Debate Team": {
        "description": "Develop public speaking and argumentation skills",
        "schedule": "Fridays, 3:30 PM - 5:30 PM",
        "schedule_details": {
            "days": ["Friday"],
            "start_time": "15:30",
            "end_time": "17:30"
        },
        "max_participants": 12,
        "participants": ["charlotte@mergington.edu", "amelia@mergington.edu"]
    },
    "Weekend Robotics Workshop": {
        "description": "Build and program robots in our state-of-the-art workshop",
        "schedule": "Saturdays, 10:00 AM - 2:00 PM",
        "schedule_details": {
            "days": ["Saturday"],
            "start_time": "10:00",
            "end_time": "14:00"
        },
        "max_participants": 15,
        "participants": ["ethan@mergington.edu", "oliver@mergington.edu"]
    },
    "Science Olympiad": {
        "description": "Weekend science competition preparation for regional and state events",
        "schedule": "Saturdays, 1:00 PM - 4:00 PM",
        "schedule_details": {
            "days": ["Saturday"],
            "start_time": "13:00",
            "end_time": "16:00"
        },
        "max_participants": 18,
        "participants": ["isabella@mergington.edu", "lucas@mergington.edu"]
    },
    "Sunday Chess Tournament": {
        "description": "Weekly tournament for serious chess players with rankings",
        "schedule": "Sundays, 2:00 PM - 5:00 PM",
        "schedule_details": {
            "days": ["Sunday"],
            "start_time": "14:00",
            "end_time": "17:00"
        },
        "max_participants": 16,
        "participants": ["william@mergington.edu", "jacob@mergington.edu"]
    }
}

initial_teachers = [
    {
        "username": "mrodriguez",
        "display_name": "Ms. Rodriguez",
        "password": hash_password("art123"),
        "role": "teacher"
    },
    {
        "username": "mchen",
        "display_name": "Mr. Chen",
        "password": hash_password("chess456"),
        "role": "teacher"
    },
    {
        "username": "principal",
        "display_name": "Principal Martinez",
        "password": hash_password("admin789"),
        "role": "admin"
    }
]
