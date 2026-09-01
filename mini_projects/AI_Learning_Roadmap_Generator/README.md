# 🧠 AI Learning Roadmap Generator

An AI-powered application that generates personalized learning
roadmaps based on a learner's domain, skill level, and available
learning time.

## 🚀 Features

- Generate personalized learning roadmaps
- Supports Beginner, Intermediate, and Advanced levels
- Customize roadmap based on available learning time
- Includes prerequisites and learning topics
- Includes practical exercises and projects
- Provides milestones and a final project
- Simple and interactive Gradio interface

## 🛠️ Tech Stack

- Python
- Gradio
- Groq API
- GPT-OSS-120B
- Google Colab

## ⚙️ How It Works

The user provides:

1. Domain / Field
2. Skill Level
3. Available Learning Time

The application sends this information to the Groq API,
which uses the GPT-OSS-120B model to generate a personalized
learning roadmap.

```text
User Input
    ↓
Gradio Interface
    ↓
Python
    ↓
Groq API
    ↓
GPT-OSS-120B
    ↓
Personalized Learning Roadmap