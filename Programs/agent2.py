from ollama import chat
from tools.hello_tool import hello_tool

messages = [
    {
        "role": "user",
        "content": "Please use the hello tool and then explain what the tool returned."
    }
]

tools = [
    {
        "type": "function",
        "function": {
            "name": "hello_tool",
            "description": "Returns a harmless greeting from a demonstration tool.",
            "parameters": {
                "type": "object",
                "properties": {},
            },
        },
    }
]

# Step 1: Ask the LLM what to do
response = chat(
    model="llama3.2:3b",
    messages=messages,
    tools=tools,
)

print("LLM response:")
print(response.message)

# Step 2: Check whether the LLM requested a tool
if response.message.tool_calls:

    for tool_call in response.message.tool_calls:

        if tool_call.function.name == "hello_tool":

            print("\nTool requested: hello_tool")

            # Step 3: Execute the tool
            result = hello_tool()

            print("Tool result:")
            print(result)

            # Step 4: Give the tool result back to the LLM
            messages.append(response.message)

            messages.append(
                {
                    "role": "tool",
                    "content": result,
                }
            )

            # Step 5: Ask the LLM for the final response
            final_response = chat(
                model="llama3.2:3b",
                messages=messages,
                tools=tools,
            )

            print("\nFinal LLM response:")
            print(final_response.message.content)
