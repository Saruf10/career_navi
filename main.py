# 1. Import necessary libraries
import os
import random
import json
from datetime import datetime, timedelta, timezone
import jwt
from dotenv import load_dotenv
from fastapi import FastAPI, Depends, HTTPException
from fastapi.security import OAuth2PasswordBearer
from pydantic import BaseModel, Field, EmailStr
from passlib.context import CryptContext
from openai import OpenAI
from fastapi.middleware.cors import CORSMiddleware
import firebase_admin
from firebase_admin import credentials, firestore

# --- Application Setup ---
load_dotenv()
app = FastAPI()

# --- CORS Middleware ---
origins = ["null", "file://"]
app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# --- Firebase Admin SDK Initialization ---
try:
    if not firebase_admin._apps:
        cred_path = os.getenv("FIREBASE_SERVICE_ACCOUNT_KEY_PATH")
        if not cred_path:
            raise ValueError("FIREBASE_SERVICE_ACCOUNT_KEY_PATH is not set in the .env file")
        cred = credentials.Certificate(cred_path)
        firebase_admin.initialize_app(cred)
        print("Firebase Admin SDK initialized successfully.")
except Exception as e:
    print(f"Firebase Admin SDK initialization failed: {e}")

db = firestore.client()

# --- Security and API Clients Setup ---
client = OpenAI(api_key=os.getenv("OPENAI_API_KEY"))

SECRET_KEY = os.getenv("SECRET_KEY")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60 * 24 
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

# --- Pydantic Models ---
class UserAuth(BaseModel): email: EmailStr; password: str = Field(..., min_length=6)
class ProfileData(BaseModel): displayName: str = Field(..., min_length=3, max_length=30); avatar: str
class UserDetailsUpdate(BaseModel): displayName: str; phoneNumber: str | None = None
class QuizData(BaseModel): skills: str; interests: str; experience: str
class StepComplete(BaseModel): stepIndex: int
class StepDetailsRequest(BaseModel): stepTitle: str; stepDescription: str
class JobDetailsRequest(BaseModel): jobTitle: str # Changed from TrendDetailsRequest
class Job(BaseModel): title: str; description: str; skills: list[str] # Changed from Trend
class JobsResponse(BaseModel): jobs: list[Job] # Changed from TrendsResponse

# --- Helper Functions ---
def verify_password(plain_password, hashed_password): return pwd_context.verify(plain_password, hashed_password)
def get_password_hash(password): return pwd_context.hash(password)
def create_access_token(data: dict):
    to_encode = data.copy()
    expire = datetime.now(timezone.utc) + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

async def get_current_user_email(token: str = Depends(oauth2_scheme)):
    credentials_exception = HTTPException(status_code=401, detail="Could not validate credentials", headers={"WWW-Authenticate": "Bearer"})
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        email: str = payload.get("sub")
        if email is None: raise credentials_exception
        return email
    except jwt.PyJWTError: raise credentials_exception

# --- API Endpoints ---
# ... (Register, Login, User Me, Profile Updates are unchanged)
@app.post("/register")
async def register(user: UserAuth):
    users_ref = db.collection('users').document(user.email)
    if users_ref.get().exists: raise HTTPException(status_code=400, detail="Email already registered")
    hashed_password = get_password_hash(user.password)
    user_data = { "email": user.email, "hashed_password": hashed_password, "profile_setup_completed": False, "quiz_completed": False, "created_at": datetime.now(timezone.utc) }
    users_ref.set(user_data)
    return {"message": "User registered successfully"}

@app.post("/token")
async def login(form_data: UserAuth):
    users_ref = db.collection('users').document(form_data.email)
    user_doc = users_ref.get()
    if not user_doc.exists: raise HTTPException(status_code=401, detail="Incorrect email or password")
    user_data = user_doc.to_dict()
    if not verify_password(form_data.password, user_data['hashed_password']): raise HTTPException(status_code=401, detail="Incorrect email or password")
    
    today = datetime.now(timezone.utc).date()
    last_login = user_data.get('last_login_date')
    streak = 1
    if last_login:
        last_login_date = last_login.date()
        if today == last_login_date + timedelta(days=1): streak = user_data.get('login_streak', 0) + 1
        elif today == last_login_date: streak = user_data.get('login_streak', 1)

    users_ref.update({'login_streak': streak, 'last_login_date': datetime.now(timezone.utc)})
    access_token = create_access_token(data={"sub": form_data.email})
    return {"access_token": access_token, "token_type": "bearer"}

@app.get("/users/me")
async def read_users_me(current_user_email: str = Depends(get_current_user_email)):
    user_doc = db.collection('users').document(current_user_email).get()
    if user_doc.exists: return user_doc.to_dict()
    raise HTTPException(status_code=404, detail="User not found")

@app.post("/update-profile")
async def update_profile(profile_data: ProfileData, current_user_email: str = Depends(get_current_user_email)):
    user_ref = db.collection('users').document(current_user_email)
    user_ref.update({ "displayName": profile_data.displayName, "avatar": profile_data.avatar, "profile_setup_completed": True, "xp": 0, "level": 1, "login_streak": 1, "last_login_date": datetime.now(timezone.utc) })
    return {"message": "Profile updated successfully"}

@app.post("/update-user-details")
async def update_user_details(details: UserDetailsUpdate, current_user_email: str = Depends(get_current_user_email)):
    user_ref = db.collection('users').document(current_user_email)
    user_ref.update({ "displayName": details.displayName, "phoneNumber": details.phoneNumber })
    return {"message": "User details updated successfully"}

@app.post("/submit-quiz")
async def submit_quiz(quiz_data: QuizData, current_user_email: str = Depends(get_current_user_email)):
    prompt = f"""
    Analyze the user's profile and generate a personalized career roadmap in a JSON object format.
    User Profile: Skills: {quiz_data.skills}, Interests: {quiz_data.interests}, Experience: {quiz_data.experience}
    JSON structure: {{ "careerTitle": "string", "summary": "string", "roadmap": [ {{ "type": "string", "title": "string", "description": "string", "xp": integer }} ] }}
    Ensure roadmap has 4-6 diverse, actionable steps (Course, Project, Certification, Internship).
    """
    try:
        response = client.chat.completions.create( model="gpt-4o-mini", response_format={"type": "json_object"}, messages=[ {"role": "system", "content": "You are a helpful career counselor AI. You must output your response in JSON format."}, {"role": "user", "content": prompt} ])
        ai_roadmap = response.choices[0].message.content
        user_ref = db.collection('users').document(current_user_email)
        user_ref.update({ "quiz_data": quiz_data.model_dump(), "ai_roadmap": ai_roadmap, "quiz_completed": True, "last_updated": datetime.now(timezone.utc), "xp": 0, "level": 1, "completed_steps": [] })
        return {"message": "Quiz submitted successfully!", "roadmap": ai_roadmap}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"An error occurred with the AI model: {str(e)}")

@app.post("/complete-step")
async def complete_step(step: StepComplete, current_user_email: str = Depends(get_current_user_email)):
    user_ref = db.collection('users').document(current_user_email)
    user_doc = user_ref.get()
    if not user_doc.exists: raise HTTPException(status_code=404, detail="User not found")
    user_data = user_doc.to_dict()
    
    roadmap_str = user_data.get("ai_roadmap", "{}")
    roadmap = json.loads(roadmap_str)

    if not roadmap or not isinstance(roadmap.get("roadmap"), list): raise HTTPException(status_code=400, detail="No roadmap found for user")
    if step.stepIndex >= len(roadmap["roadmap"]): raise HTTPException(status_code=400, detail="Invalid step index")

    xp_gain = roadmap["roadmap"][step.stepIndex].get("xp", 50)
    new_xp = user_data.get("xp", 0) + xp_gain
    new_level = (new_xp // 250) + 1
    completed_steps = user_data.get("completed_steps", [])
    if step.stepIndex not in completed_steps: completed_steps.append(step.stepIndex)
    user_ref.update({"xp": new_xp, "level": new_level, "completed_steps": completed_steps})
    return {"message": "Step completed!", "new_xp": new_xp, "new_level": new_level}


@app.post("/get-step-details")
async def get_step_details(request: StepDetailsRequest, current_user_email: str = Depends(get_current_user_email)):
    prompt = f"""
    A user is working on a step in their career roadmap: '{request.stepTitle}' (Description: '{request.stepDescription}'). 
    Provide a detailed guide: 1. Explain its importance. 2. List 3-5 sub-tasks. 3. Suggest 2-3 real online courses with generic, valid search URLs (e.g., https://www.coursera.org/search?query=...).
    Format as clean Markdown.
    """
    try:
        response = client.chat.completions.create( model="gpt-4o-mini", messages=[ {"role": "system", "content": "You are a helpful career counselor AI."}, {"role": "user", "content": prompt} ])
        return {"details": response.choices[0].message.content}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error fetching details from OpenAI: {str(e)}")

# NEW: Replaced /job-trends with /recommended-jobs
@app.post("/recommended-jobs", response_model=JobsResponse)
async def get_recommended_jobs(current_user_email: str = Depends(get_current_user_email)):
    user_doc = db.collection('users').document(current_user_email).get()
    if not user_doc.exists or not user_doc.to_dict().get('quiz_data'):
        raise HTTPException(status_code=404, detail="User or quiz data not found")
    
    quiz_data = user_doc.to_dict()['quiz_data']
    prompt = f"""
    Based on the user's profile (Skills: {quiz_data['skills']}, Interests: {quiz_data['interests']}), recommend 3 diverse and suitable job roles.
    For each role, provide a "title", a brief "description" (2 sentences max), and a list of 3-4 essential "skills".
    Return the output as a JSON object with a single key "jobs" which is a list of these job roles.
    """
    try:
        response = client.chat.completions.create(
            model="gpt-4o-mini",
            response_format={"type": "json_object"},
            messages=[
                {"role": "system", "content": "You are a career recommendation AI. Output JSON."},
                {"role": "user", "content": prompt}
            ]
        )
        jobs_data = json.loads(response.choices[0].message.content)
        return JobsResponse.model_validate(jobs_data)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error fetching recommended jobs from OpenAI: {str(e)}")

@app.post("/dashboard-summary")
async def get_dashboard_summary(current_user_email: str = Depends(get_current_user_email)):
    user_doc = db.collection('users').document(current_user_email).get()
    if not user_doc.exists or not user_doc.to_dict().get('quiz_data'):
        raise HTTPException(status_code=404, detail="User or quiz data not found")
    
    quiz_data = user_doc.to_dict()['quiz_data']
    prompt = f"""
    Based on the user's quiz data (Skills: {quiz_data['skills']}, Interests: {quiz_data['interests']}), generate three short, insightful summaries for a dashboard.
    Provide the output as a single JSON object with three keys: "skill_based", "interest_based", and "experience_based".
    Each value should be a single, concise sentence (max 20 words).
    """
    try:
        response = client.chat.completions.create(model="gpt-4o-mini", response_format={"type": "json_object"}, messages=[{"role": "system", "content": "You are a helpful career AI. Output JSON."}, {"role": "user", "content": prompt}])
        summary_data = json.loads(response.choices[0].message.content)
        return summary_data
    except Exception as e:
        raise HTTPException(status_code=500, detail="Failed to generate dashboard summary.")

# NEW: Replaced /trend-details with /job-details
@app.post("/job-details")
async def get_job_details(request: JobDetailsRequest, current_user_email: str = Depends(get_current_user_email)):
    prompt = f"""
    Generate a detailed report for the job role: '{request.jobTitle}'.
    The report should include:
    1.  **Overview:** A paragraph summarizing the role and its importance.
    2.  **Key Responsibilities:** A bulleted list of 3-5 primary duties.
    3.  **Required Skills:** A bulleted list of the most crucial technical and soft skills.
    4.  **Career Outlook:** A brief paragraph on future prospects and salary expectations based on general knowledge up to 2023.
    Format the entire response in clean Markdown.
    """
    try:
        response = client.chat.completions.create(
            model="gpt-4o-mini",
            messages=[
                {"role": "system", "content": "You are a helpful career AI."},
                {"role": "user", "content": prompt}
            ]
        )
        return {"details": response.choices[0].message.content}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error fetching job details from OpenAI: {str(e)}")

