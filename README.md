# Smart Quizzer
Smart Quizzer is a dynamic, interactive web application built using Flask, MySQL, and Python, designed to help users create and attempt quizzes on various topics. The application features user authentication, topic selection, and AI-powered quiz generation using the Google Gemini API.

## Features
- **User Authentication:** Secure registration and login with hashed passwords.
- **Topic & Skill Selection:** Choose your subject, topic, skill level, and number of questions.
- **AI Quiz Generation:** Generate multiple-choice questions dynamically with Google Gemini API.
- **Fallback Questions:** Provides default questions if the API fails or returns invalid data.
- **Quiz Management:** Take quizzes, submit answers, and view scores with detailed results.
- **Database Integration:** Stores user credentials securely in MySQL.
- **Server-Side Sessions:** Keeps user sessions secure using Flask-Session.
- **User-Friendly Interface:** Responsive HTML templates with flash messages for feedback.

## Tech Stack
- **Backend:** Python, Flask, Flask-Bcrypt, Flask-Session
- **Database:** MySQL
- **Frontend:** HTML, CSS, Jinja2 Templates
- **API:** Google Gemini API
- **Libraries:** requests, json, re

## Usage
1. Clone the repository:
   ```bash
   git clone https://github.com/yourusername/smart-quizzer.git
