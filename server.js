const express = require('express');
const { createClient } = require('@supabase/supabase-js');
const multer = require('multer');
const cors = require('cors');
const path = require('path');
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 3000;

// Middleware
app.use(cors());
app.use(express.json());
app.use(express.static('public'));

// Supabase
const supabase = createClient(
    process.env.SUPABASE_URL,
    process.env.SUPABASE_ANON_KEY
);

// File upload
const storage = multer.diskStorage({
    destination: './uploads/',
    filename: (req, file, cb) => {
        cb(null, Date.now() + '-' + file.originalname);
    }
});
const upload = multer({ storage: storage });

// ========== API ROUTES ==========

// Health check
app.get('/api/health', (req, res) => {
    res.json({ status: 'OK', message: 'HireIND_US is running!' });
});

// Student Registration
app.post('/api/students/register', upload.single('resume'), async (req, res) => {
    try {
        const { full_name, email, phone, current_city, current_state, 
                university_name, graduation_date, visa_type, linkedin_url, 
                github_url, skills } = req.body;
        
        let resume_url = null;
        if (req.file) {
            const fileName = Date.now() + '-' + req.file.originalname;
            const { data, error } = await supabase.storage
                .from('resumes')
                .upload(fileName, req.file.buffer);
            if (!error) {
                const { data: urlData } = supabase.storage
                    .from('resumes')
                    .getPublicUrl(fileName);
                resume_url = urlData.publicUrl;
            }
        }
        
        // Check if user exists
        let { data: existingUser } = await supabase
            .from('users')
            .select('id')
            .eq('email', email)
            .single();
        
        let userId;
        if (!existingUser) {
            const { data: newUser, error: userError } = await supabase
                .from('users')
                .insert({ email, full_name, role: 'student' })
                .select();
            if (userError) throw userError;
            userId = newUser[0].id;
        } else {
            userId = existingUser.id;
        }
        
        // Insert student
        const { data: student, error } = await supabase
            .from('students')
            .insert({
                user_id: userId,
                full_name,
                email,
                phone,
                current_city,
                current_state,
                university_name,
                graduation_date,
                visa_type,
                linkedin_url,
                github_url,
                resume_url,
                profile_complete: true
            })
            .select();
        
        if (error) throw error;
        
        // Insert skills
        if (skills) {
            const skillArray = skills.split(',').map(s => s.trim());
            for (const skillName of skillArray) {
                let { data: skill } = await supabase
                    .from('skills')
                    .select('id')
                    .eq('skill_name', skillName)
                    .single();
                
                if (!skill) {
                    const { data: newSkill } = await supabase
                        .from('skills')
                        .insert({ skill_name: skillName })
                        .select();
                    if (newSkill) skill = newSkill[0];
                }
                
                if (skill && student[0]) {
                    await supabase
                        .from('student_skills')
                        .insert({
                            student_id: student[0].id,
                            skill_id: skill.id
                        });
                }
            }
        }
        
        res.json({ 
            success: true, 
            message: 'Student registered successfully!',
            student: student[0]
        });
        
    } catch (error) {
        console.error('Registration error:', error);
        res.status(500).json({ success: false, error: error.message });
    }
});

// Get all students
app.get('/api/students', async (req, res) => {
    try {
        const { state, visa } = req.query;
        
        let query = supabase
            .from('students')
            .select('*')
            .eq('profile_complete', true);
        
        if (state) query = query.eq('current_state', state);
        if (visa) query = query.eq('visa_type', visa);
        
        const { data: students, error } = await query;
        
        if (error) throw error;
        
        res.json({ success: true, count: students?.length || 0, students: students || [] });
        
    } catch (error) {
        res.status(500).json({ success: false, error: error.message });
    }
});

// Get single student
app.get('/api/students/:id', async (req, res) => {
    try {
        const { id } = req.params;
        
        const { data: student, error } = await supabase
            .from('students')
            .select(`
                *,
                student_skills(
                    skills(skill_name)
                )
            `)
            .eq('id', id)
            .single();
        
        if (error) throw error;
        
        res.json({ success: true, student });
        
    } catch (error) {
        res.status(500).json({ success: false, error: error.message });
    }
});

// Recruiter registration
app.post('/api/recruiters/register', async (req, res) => {
    try {
        const { company_name, recruiter_name, email, company_website } = req.body;
        
        const { data: recruiter, error } = await supabase
            .from('recruiters')
            .insert({
                company_name,
                recruiter_name,
                email,
                company_website,
                verified: true
            })
            .select();
        
        if (error) throw error;
        
        res.json({ 
            success: true, 
            message: 'Recruiter registered successfully!',
            recruiter: recruiter[0]
        });
        
    } catch (error) {
        res.status(500).json({ success: false, error: error.message });
    }
});

// Get recruiter stats
app.get('/api/recruiter/stats', async (req, res) => {
    try {
        const { data: students } = await supabase
            .from('students')
            .select('visa_type');
        
        const total = students?.length || 0;
        const opt = students?.filter(s => 
            s.visa_type === 'OPT_1st_year' || 
            s.visa_type === 'OPT_2nd_year' || 
            s.visa_type === 'STEM_OPT'
        ).length || 0;
        
        res.json({ success: true, totalStudents: total, optStudents: opt });
        
    } catch (error) {
        res.status(500).json({ success: false, error: error.message });
    }
});

// Start server
app.listen(PORT, () => {
    console.log(`🚀 HireIND_US running on http://localhost:${PORT}`);
});

// Create uploads folder if not exists
const fs = require('fs');
if (!fs.existsSync('./uploads')) {
    fs.mkdirSync('./uploads');
}
