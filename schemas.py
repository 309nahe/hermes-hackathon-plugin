"""Tool JSON schemas for hermes-hackathon-plugin."""

PING_SCHEMA = {
    "name": "ping",
    "description": "Health-check tool. Returns a greeting for the given name.",
    "parameters": {
        "type": "object",
        "properties": {
            "name": {"type": "string", "description": "Name to greet"},
        },
        "required": [],
    },
}
