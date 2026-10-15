from ollama import chat
from tools.hello_tool import hello_tool

messages = [
    {
        "role": "user",
        "content": "Please use the hello tool and tell me what it returns."
    }
]

response = chat(
    model="llama3.2:3b",
    messages=messages,
    tools=[
        {
            "type": "function",
            "function": {
                "name": "hello_tool",
                "description": "Returns a greeting from tool.",
                "parameters": {
                    "type": "object",
                    "properties": {},
                },
            },
        }
    ],
)

print("Model response:")
print(response.message)

if response.message.tool_calls:
    print("\nTool requested!")

    result = hello_tool()

    print("Tool result:")
    print(result)
