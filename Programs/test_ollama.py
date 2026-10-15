from ollama import chat

response = chat(
    model="llama3.2:3b",
    messages=[
        {
            "role": "user",
            "content": "Mahabharat"
        }
    ],
)

print(response.message.content)
