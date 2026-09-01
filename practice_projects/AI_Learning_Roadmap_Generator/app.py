import os
import gradio as gr
from groq import Groq


# Connect to Groq API
client = Groq(
    api_key=os.environ.get("GROQ_API_KEY")
)


# Generate learning roadmap
def generate_roadmap(domain, level, time):

    prompt = f"""
You are an expert learning roadmap designer.

Create a personalized learning roadmap for the following learner:

Domain/Field: {domain}
Skill Level: {level}
Available Learning Time: {time}

The roadmap should include:

1. Prerequisites
2. Topics to learn in order
3. Practical exercises
4. Projects
5. Milestones
6. Final project

Make the roadmap realistic for the learner's skill level
and available learning time.

Organize the roadmap into clear stages.

Use Markdown formatting.
"""

    response = client.chat.completions.create(
        model="openai/gpt-oss-120b",
        messages=[
            {
                "role": "user",
                "content": prompt
            }
        ]
    )

    return response.choices[0].message.content


# Gradio UI
with gr.Blocks(title="AI Learning Roadmap Generator") as app:

    gr.Markdown(
        """
        # 🧠 AI Learning Roadmap Generator

        Create a personalized learning roadmap based on your
        field, skill level, and available learning time.
        """
    )

    domain = gr.Textbox(
        label="📚 Domain / Field",
        placeholder="e.g. Data Science"
    )

    level = gr.Dropdown(
        choices=[
            "Beginner",
            "Intermediate",
            "Advanced"
        ],
        label="🎯 Skill Level",
        value="Beginner"
    )

    time = gr.Textbox(
        label="⏰ Time to Learn",
        placeholder="e.g. 3 months"
    )

    generate_button = gr.Button(
        "🚀 Generate Roadmap"
    )

    output = gr.Markdown(
        label="🗺️ Your Roadmap"
    )

    generate_button.click(
        fn=generate_roadmap,
        inputs=[domain, level, time],
        outputs=output
    )


# Launch application
if __name__ == "__main__":
    app.launch()