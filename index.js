var __defProp = Object.defineProperty;
var __export = (target, all) => {
  for (var name in all)
    __defProp(target, name, { get: all[name], enumerable: true });
};

// server/index.ts
import "dotenv/config";
import express2 from "express";

// server/routes.ts
import { createServer } from "http";

// server/auth.ts
import passport from "passport";
import { Strategy as LocalStrategy } from "passport-local";
import session2 from "express-session";
import { scrypt, randomBytes, timingSafeEqual } from "crypto";
import { promisify } from "util";

// server/db.ts
import { drizzle } from "drizzle-orm/postgres-js";
import postgres from "postgres";

// shared/schema.ts
var schema_exports = {};
__export(schema_exports, {
  answerSheets: () => answerSheets,
  answerSheetsRelations: () => answerSheetsRelations,
  courses: () => courses,
  coursesRelations: () => coursesRelations,
  enrollments: () => enrollments,
  enrollmentsRelations: () => enrollmentsRelations,
  examStatusEnum: () => examStatusEnum,
  exams: () => exams,
  examsRelations: () => examsRelations,
  gradingStatusEnum: () => gradingStatusEnum,
  insertAnswerSheetSchema: () => insertAnswerSheetSchema,
  insertCourseSchema: () => insertCourseSchema,
  insertEnrollmentSchema: () => insertEnrollmentSchema,
  insertExamSchema: () => insertExamSchema,
  insertQuestionGradeSchema: () => insertQuestionGradeSchema,
  insertQuestionSchema: () => insertQuestionSchema,
  insertUserSchema: () => insertUserSchema,
  questionGrades: () => questionGrades,
  questionGradesRelations: () => questionGradesRelations,
  questions: () => questions,
  questionsRelations: () => questionsRelations,
  schema: () => schema,
  userRoleEnum: () => userRoleEnum,
  users: () => users,
  usersRelations: () => usersRelations
});
import { pgTable, text, serial, integer, timestamp, json, pgEnum } from "drizzle-orm/pg-core";
import { createInsertSchema } from "drizzle-zod";
import { relations } from "drizzle-orm";
var userRoleEnum = pgEnum("user_role", ["admin", "instructor", "second_instructor", "staff", "student"]);
var examStatusEnum = pgEnum("exam_status", ["scheduled", "in_progress", "completed", "cancelled"]);
var gradingStatusEnum = pgEnum("grading_status", ["pending", "in_progress", "completed", "reviewed"]);
var users = pgTable("users", {
  id: serial("id").primaryKey(),
  username: text("username").notNull().unique(),
  password: text("password").notNull(),
  fullName: text("full_name").notNull(),
  email: text("email").notNull().unique(),
  role: userRoleEnum("role").notNull(),
  department: text("department"),
  studentId: text("student_id").unique(),
  createdAt: timestamp("created_at").defaultNow().notNull()
});
var usersRelations = relations(users, ({ many }) => ({
  examsAsInstructor: many(exams, { relationName: "instructor" }),
  examsAsSecondInstructor: many(exams, { relationName: "second_instructor" }),
  answerSheets: many(answerSheets)
}));
var courses = pgTable("courses", {
  id: serial("id").primaryKey(),
  code: text("code").notNull().unique(),
  name: text("name").notNull(),
  department: text("department").notNull(),
  description: text("description"),
  createdAt: timestamp("created_at").defaultNow().notNull()
});
var coursesRelations = relations(courses, ({ many }) => ({
  exams: many(exams),
  enrollments: many(enrollments)
}));
var enrollments = pgTable("enrollments", {
  id: serial("id").primaryKey(),
  userId: integer("user_id").notNull().references(() => users.id, { onDelete: "cascade" }),
  courseId: integer("course_id").notNull().references(() => courses.id, { onDelete: "cascade" }),
  academicYear: text("academic_year").notNull(),
  semester: text("semester").notNull(),
  createdAt: timestamp("created_at").defaultNow().notNull()
});
var enrollmentsRelations = relations(enrollments, ({ one }) => ({
  user: one(users, { fields: [enrollments.userId], references: [users.id] }),
  course: one(courses, { fields: [enrollments.courseId], references: [courses.id] })
}));
var exams = pgTable("exams", {
  id: serial("id").primaryKey(),
  courseId: integer("course_id").notNull().references(() => courses.id, { onDelete: "cascade" }),
  title: text("title").notNull(),
  description: text("description"),
  examDate: timestamp("exam_date").notNull(),
  duration: integer("duration").notNull(),
  // in minutes
  totalMarks: integer("total_marks").notNull(),
  venue: text("venue"),
  instructorId: integer("instructor_id").notNull().references(() => users.id),
  secondInstructorId: integer("second_instructor_id").references(() => users.id),
  status: examStatusEnum("status").notNull().default("scheduled"),
  createdAt: timestamp("created_at").defaultNow().notNull()
});
var examsRelations = relations(exams, ({ one, many }) => ({
  course: one(courses, { fields: [exams.courseId], references: [courses.id] }),
  instructor: one(users, { fields: [exams.instructorId], references: [users.id], relationName: "instructor" }),
  secondInstructor: one(users, { fields: [exams.secondInstructorId], references: [users.id], relationName: "second_instructor" }),
  answerSheets: many(answerSheets),
  questions: many(questions)
}));
var questions = pgTable("questions", {
  id: serial("id").primaryKey(),
  examId: integer("exam_id").notNull().references(() => exams.id, { onDelete: "cascade" }),
  questionNumber: integer("question_number").notNull(),
  questionText: text("question_text").notNull(),
  marks: integer("marks").notNull(),
  createdAt: timestamp("created_at").defaultNow().notNull()
});
var questionsRelations = relations(questions, ({ one }) => ({
  exam: one(exams, { fields: [questions.examId], references: [exams.id] })
}));
var answerSheets = pgTable("answer_sheets", {
  id: serial("id").primaryKey(),
  examId: integer("exam_id").notNull().references(() => exams.id, { onDelete: "cascade" }),
  studentId: integer("student_id").notNull().references(() => users.id, { onDelete: "cascade" }),
  filePath: text("file_path").notNull(),
  uploadedAt: timestamp("uploaded_at").defaultNow().notNull(),
  status: gradingStatusEnum("status").notNull().default("pending"),
  gradedBy: integer("graded_by").references(() => users.id),
  reviewedBy: integer("reviewed_by").references(() => users.id),
  totalScore: integer("total_score"),
  feedback: text("feedback"),
  annotations: json("annotations").$type(),
  gradedAt: timestamp("graded_at"),
  reviewedAt: timestamp("reviewed_at")
});
var answerSheetsRelations = relations(answerSheets, ({ one, many }) => ({
  exam: one(exams, { fields: [answerSheets.examId], references: [exams.id] }),
  student: one(users, { fields: [answerSheets.studentId], references: [users.id] }),
  grader: one(users, { fields: [answerSheets.gradedBy], references: [users.id] }),
  reviewer: one(users, { fields: [answerSheets.reviewedBy], references: [users.id] }),
  questionGrades: many(questionGrades)
}));
var questionGrades = pgTable("question_grades", {
  id: serial("id").primaryKey(),
  answerSheetId: integer("answer_sheet_id").notNull().references(() => answerSheets.id, { onDelete: "cascade" }),
  questionId: integer("question_id").notNull().references(() => questions.id, { onDelete: "cascade" }),
  score: integer("score").notNull(),
  feedback: text("feedback"),
  createdAt: timestamp("created_at").defaultNow().notNull()
});
var questionGradesRelations = relations(questionGrades, ({ one }) => ({
  answerSheet: one(answerSheets, { fields: [questionGrades.answerSheetId], references: [answerSheets.id] }),
  question: one(questions, { fields: [questionGrades.questionId], references: [questions.id] })
}));
var insertUserSchema = createInsertSchema(users).omit({ id: true, createdAt: true });
var insertCourseSchema = createInsertSchema(courses).omit({ id: true, createdAt: true });
var insertEnrollmentSchema = createInsertSchema(enrollments).omit({ id: true, createdAt: true });
var insertExamSchema = createInsertSchema(exams).omit({ id: true, createdAt: true, status: true });
var insertQuestionSchema = createInsertSchema(questions).omit({ id: true, createdAt: true });
var insertAnswerSheetSchema = createInsertSchema(answerSheets).omit({
  id: true,
  uploadedAt: true,
  status: true,
  gradedBy: true,
  reviewedBy: true,
  totalScore: true,
  feedback: true,
  annotations: true,
  gradedAt: true,
  reviewedAt: true
});
var insertQuestionGradeSchema = createInsertSchema(questionGrades).omit({ id: true, createdAt: true });
var schema = {
  users,
  courses,
  enrollments,
  exams,
  questions,
  answerSheets,
  questionGrades,
  userRoleEnum,
  examStatusEnum,
  gradingStatusEnum
};

// server/db.ts
if (!process.env.DATABASE_URL) {
  throw new Error("DATABASE_URL is not set");
}
var queryClient = postgres(process.env.DATABASE_URL, {
  max: 10,
  idle_timeout: 20,
  connect_timeout: 10
});
var db = drizzle(queryClient, { schema: schema_exports });

// server/storage.ts
import { eq, and, desc, sql } from "drizzle-orm";
import session from "express-session";
import MemoryStore from "memorystore";
var MemStoreFactory = MemoryStore(session);
var DatabaseStorage = class {
  sessionStore;
  constructor() {
    this.sessionStore = new MemStoreFactory({
      checkPeriod: 864e5
      // prune expired entries every 24h
    });
  }
  // User-related operations
  async getUser(id) {
    const [user] = await db.select().from(users).where(eq(users.id, id));
    return user;
  }
  async getUserByUsername(username) {
    const [user] = await db.select().from(users).where(eq(users.username, username));
    return user;
  }
  async createUser(user) {
    const [createdUser] = await db.insert(users).values(user).returning();
    return createdUser;
  }
  async updateUser(id, user) {
    const [updatedUser] = await db.update(users).set(user).where(eq(users.id, id)).returning();
    return updatedUser;
  }
  async deleteUser(id) {
    const result = await db.delete(users).where(eq(users.id, id));
    return true;
  }
  async listUsers(role) {
    if (role) {
      return db.select().from(users).where(eq(users.role, role));
    }
    return db.select().from(users);
  }
  // Course-related operations
  async getCourse(id) {
    const [course] = await db.select().from(courses).where(eq(courses.id, id));
    return course;
  }
  async getCourseByCode(code) {
    const [course] = await db.select().from(courses).where(eq(courses.code, code));
    return course;
  }
  async createCourse(course) {
    const [createdCourse] = await db.insert(courses).values(course).returning();
    return createdCourse;
  }
  async updateCourse(id, course) {
    const [updatedCourse] = await db.update(courses).set(course).where(eq(courses.id, id)).returning();
    return updatedCourse;
  }
  async deleteCourse(id) {
    await db.delete(courses).where(eq(courses.id, id));
    return true;
  }
  async listCourses() {
    return db.select().from(courses);
  }
  // Enrollment-related operations
  async createEnrollment(enrollment) {
    const [createdEnrollment] = await db.insert(enrollments).values(enrollment).returning();
    return createdEnrollment;
  }
  async deleteEnrollment(id) {
    await db.delete(enrollments).where(eq(enrollments.id, id));
    return true;
  }
  async getStudentsByCoursesId(courseId) {
    const results = await db.select().from(users).innerJoin(
      enrollments,
      and(
        eq(users.id, enrollments.userId),
        eq(enrollments.courseId, courseId)
      )
    ).where(eq(users.role, "student"));
    return results.map(({ users: users2 }) => users2);
  }
  async getCoursesByStudentId(studentId) {
    const results = await db.select().from(courses).innerJoin(
      enrollments,
      and(
        eq(courses.id, enrollments.courseId),
        eq(enrollments.userId, studentId)
      )
    );
    return results.map(({ courses: courses2 }) => courses2);
  }
  // Exam-related operations
  async getExam(id) {
    const [exam] = await db.select().from(exams).where(eq(exams.id, id));
    return exam;
  }
  async createExam(exam) {
    const [createdExam] = await db.insert(exams).values(exam).returning();
    return createdExam;
  }
  async updateExam(id, exam) {
    const [updatedExam] = await db.update(exams).set(exam).where(eq(exams.id, id)).returning();
    return updatedExam;
  }
  async deleteExam(id) {
    await db.delete(exams).where(eq(exams.id, id));
    return true;
  }
  async listExams() {
    return db.select().from(exams).orderBy(desc(exams.examDate));
  }
  async getExamsByInstructorId(instructorId) {
    return db.select().from(exams).where(eq(exams.instructorId, instructorId)).orderBy(desc(exams.examDate));
  }
  async getExamsByStudentId(studentId) {
    const enrolledCourses = await this.getCoursesByStudentId(studentId);
    const courseIds = enrolledCourses.map((course) => course.id);
    if (courseIds.length === 0) return [];
    return db.select().from(exams).where(sql`${exams.courseId} IN ${courseIds}`).orderBy(desc(exams.examDate));
  }
  // Question-related operations
  async createQuestion(question) {
    const [createdQuestion] = await db.insert(questions).values(question).returning();
    return createdQuestion;
  }
  async getQuestionsByExamId(examId) {
    return db.select().from(questions).where(eq(questions.examId, examId)).orderBy(questions.questionNumber);
  }
  // Answer Sheet operations
  async createAnswerSheet(answerSheet) {
    const [createdAnswerSheet] = await db.insert(answerSheets).values(answerSheet).returning();
    return createdAnswerSheet;
  }
  async getAnswerSheet(id) {
    const [answerSheet] = await db.select().from(answerSheets).where(eq(answerSheets.id, id));
    return answerSheet;
  }
  async updateAnswerSheet(id, updates) {
    const [updatedAnswerSheet] = await db.update(answerSheets).set(updates).where(eq(answerSheets.id, id)).returning();
    return updatedAnswerSheet;
  }
  async getAnswerSheetsByExamId(examId) {
    return db.select().from(answerSheets).where(eq(answerSheets.examId, examId));
  }
  async getAnswerSheetsByStudentId(studentId) {
    return db.select().from(answerSheets).where(eq(answerSheets.studentId, studentId));
  }
  async getPendingGradingByInstructorId(instructorId) {
    const result = await db.select({
      exam: exams,
      answersheets_count: sql`count(${answerSheets.id})`,
      graded_count: sql`count(case when ${answerSheets.status} = 'completed' then 1 end)`
    }).from(exams).leftJoin(answerSheets, eq(exams.id, answerSheets.examId)).where(eq(exams.instructorId, instructorId)).groupBy(exams.id).having(sql`count(${answerSheets.id}) > 0`).orderBy(desc(exams.examDate));
    return result;
  }
  // Question Grading operations
  async createQuestionGrade(grade) {
    const [createdGrade] = await db.insert(questionGrades).values(grade).returning();
    return createdGrade;
  }
  async updateQuestionGrade(id, updates) {
    const [updatedGrade] = await db.update(questionGrades).set(updates).where(eq(questionGrades.id, id)).returning();
    return updatedGrade;
  }
  async getQuestionGradesByAnswerSheetId(answerSheetId) {
    return db.select().from(questionGrades).where(eq(questionGrades.answerSheetId, answerSheetId));
  }
};
var storage = new DatabaseStorage();

// server/auth.ts
var scryptAsync = promisify(scrypt);
async function hashPassword(password) {
  const salt = randomBytes(16).toString("hex");
  const buf = await scryptAsync(password, salt, 64);
  return `${buf.toString("hex")}.${salt}`;
}
async function comparePasswords(supplied, stored) {
  const [hashed, salt] = stored.split(".");
  const hashedBuf = Buffer.from(hashed, "hex");
  const suppliedBuf = await scryptAsync(supplied, salt, 64);
  return timingSafeEqual(hashedBuf, suppliedBuf);
}
function setupAuth(app2) {
  if (!process.env.SESSION_SECRET) {
    console.warn("No SESSION_SECRET set, using a default secret (not secure for production)");
  }
  const sessionSettings = {
    secret: process.env.SESSION_SECRET || "exam-management-system-secret-key",
    resave: false,
    saveUninitialized: false,
    store: storage.sessionStore,
    cookie: {
      secure: process.env.NODE_ENV === "production",
      maxAge: 24 * 60 * 60 * 1e3
      // 24 hours
    }
  };
  app2.set("trust proxy", 1);
  app2.use(session2(sessionSettings));
  app2.use(passport.initialize());
  app2.use(passport.session());
  passport.use(
    new LocalStrategy(async (username, password, done) => {
      try {
        const user = await storage.getUserByUsername(username);
        if (!user || !await comparePasswords(password, user.password)) {
          return done(null, false);
        } else {
          return done(null, user);
        }
      } catch (err) {
        return done(err);
      }
    })
  );
  passport.serializeUser((user, done) => done(null, user.id));
  passport.deserializeUser(async (id, done) => {
    try {
      const user = await storage.getUser(id);
      done(null, user);
    } catch (err) {
      done(err);
    }
  });
  app2.post("/api/register", async (req, res, next) => {
    try {
      const existingUser = await storage.getUserByUsername(req.body.username);
      if (existingUser) {
        return res.status(400).send("Username already exists");
      }
      const userData = { ...req.body };
      if (userData.role !== "student") {
        delete userData.studentId;
      }
      const user = await storage.createUser({
        ...userData,
        password: await hashPassword(userData.password)
      });
      const userResponse = { ...user };
      delete userResponse.password;
      req.login(user, (err) => {
        if (err) return next(err);
        res.status(201).json(userResponse);
      });
    } catch (err) {
      next(err);
    }
  });
  app2.post("/api/login", passport.authenticate("local"), (req, res) => {
    const userResponse = { ...req.user };
    delete userResponse.password;
    res.status(200).json(userResponse);
  });
  app2.post("/api/logout", (req, res, next) => {
    req.logout((err) => {
      if (err) return next(err);
      res.sendStatus(200);
    });
  });
  app2.get("/api/user", (req, res) => {
    if (!req.isAuthenticated()) return res.sendStatus(401);
    const userResponse = { ...req.user };
    delete userResponse.password;
    res.json(userResponse);
  });
}

// server/routes.ts
import { scrypt as scrypt2, randomBytes as randomBytes2 } from "crypto";
import { promisify as promisify2 } from "util";
import multer from "multer";
import path from "path";
import fs from "fs";
import util from "util";
import { ZodError } from "zod";
import { fromZodError } from "zod-validation-error";
import { eq as eq2 } from "drizzle-orm";
var scryptAsync2 = promisify2(scrypt2);
async function hashPassword2(password) {
  const salt = randomBytes2(16).toString("hex");
  const buf = await scryptAsync2(password, salt, 64);
  return `${buf.toString("hex")}.${salt}`;
}
var uploadDir = path.join(process.cwd(), "uploads");
if (!fs.existsSync(uploadDir)) {
  fs.mkdirSync(uploadDir, { recursive: true });
}
var storage_config = multer.diskStorage({
  destination: uploadDir,
  filename: (req, file, cb) => {
    const uniqueSuffix = Date.now() + "-" + Math.round(Math.random() * 1e9);
    cb(null, file.fieldname + "-" + uniqueSuffix + path.extname(file.originalname));
  }
});
var upload = multer({
  storage: storage_config,
  limits: {
    fileSize: 10 * 1024 * 1024
    // 10MB limit
  },
  fileFilter: (req, file, cb) => {
    if (file.mimetype === "application/pdf") {
      cb(null, true);
    } else {
      cb(null, false);
    }
  }
});
var isAuthenticated = (req, res, next) => {
  if (req.isAuthenticated()) {
    return next();
  }
  res.status(401).json({ message: "Unauthorized" });
};
var hasRole = (roles) => {
  return (req, res, next) => {
    if (!req.isAuthenticated()) {
      return res.status(401).json({ message: "Unauthorized" });
    }
    if (!roles.includes(req.user.role)) {
      return res.status(403).json({ message: "Forbidden - Insufficient permissions" });
    }
    next();
  };
};
var requireAuth = (req, res, next) => {
  if (!req.user) {
    return res.status(401).json({ error: "Unauthorized" });
  }
  next();
};
async function registerRoutes(app2) {
  setupAuth(app2);
  app2.get("/api/files/:filename", (req, res) => {
    const filename = req.params.filename;
    const filePath = path.join(uploadDir, filename);
    if (!fs.existsSync(filePath)) {
      return res.status(404).json({ message: "File not found" });
    }
    res.setHeader("Content-Type", "application/pdf");
    res.setHeader("Content-Disposition", `inline; filename="${filename}"`);
    fs.createReadStream(filePath).pipe(res);
  });
  app2.post("/api/files/save-annotated", (req, res) => {
    try {
      const { filePath, annotations } = req.body;
      if (!filePath || !annotations) {
        return res.status(400).json({ error: "Missing required fields" });
      }
      const timestamp2 = (/* @__PURE__ */ new Date()).toISOString().replace(/:/g, "-");
      const originalFilename = path.basename(filePath);
      const fileExtension = path.extname(originalFilename);
      const baseName = path.basename(originalFilename, fileExtension);
      const newFilename = `${baseName}_annotated_${timestamp2}${fileExtension}`;
      const savedPath = path.join(uploadDir, newFilename);
      const annotationData = {
        originalFilePath: filePath,
        newFilePath: newFilename,
        annotations,
        timestamp: (/* @__PURE__ */ new Date()).toISOString()
      };
      const annotationDataPath = path.join(uploadDir, `${baseName}_annotations_${timestamp2}.json`);
      fs.writeFileSync(annotationDataPath, JSON.stringify(annotationData, null, 2));
      fs.copyFileSync(path.join(uploadDir, originalFilename), savedPath);
      return res.status(200).json({
        success: true,
        message: "Annotations saved successfully",
        savedFilePath: newFilename
      });
    } catch (error) {
      console.error("Error saving annotated PDF:", error);
      return res.status(500).json({ error: "Failed to save annotated PDF" });
    }
  });
  const samplePdfPath = path.join(uploadDir, "sample-answer-sheet.pdf");
  if (!fs.existsSync(samplePdfPath)) {
    fs.writeFileSync(samplePdfPath, `%PDF-1.7
1 0 obj
<</Type/Catalog/Pages 2 0 R>>
endobj
2 0 obj
<</Type/Pages/Kids[3 0 R 4 0 R 5 0 R]/Count 3>>
endobj
3 0 obj
<</Type/Page/Parent 2 0 R/MediaBox[0 0 612 792]/Resources<</Font<</F1<</Type/Font/Subtype/Type1/BaseFont/Helvetica>>/F2<</Type/Font/Subtype/Type1/BaseFont/Helvetica-Bold>>>>>>/Contents 6 0 R>>
endobj
4 0 obj
<</Type/Page/Parent 2 0 R/MediaBox[0 0 612 792]/Resources<</Font<</F1<</Type/Font/Subtype/Type1/BaseFont/Helvetica>>/F2<</Type/Font/Subtype/Type1/BaseFont/Helvetica-Bold>>>>>>/Contents 7 0 R>>
endobj
5 0 obj
<</Type/Page/Parent 2 0 R/MediaBox[0 0 612 792]/Resources<</Font<</F1<</Type/Font/Subtype/Type1/BaseFont/Helvetica>>/F2<</Type/Font/Subtype/Type1/BaseFont/Helvetica-Bold>>>>>>/Contents 8 0 R>>
endobj
6 0 obj
<</Length 2500>>
stream
BT
/F2 24 Tf
200 730 Td
(Student Exam Answer Sheet) Tj
ET

BT
/F1 12 Tf
50 700 Td
(Student: John Student) Tj
0 -20 Td
(Student ID: CS2023001) Tj
0 -20 Td
(Course: CS101 - Introduction to Computer Science) Tj
0 -20 Td
(Exam Date: April 5, 2025) Tj
0 -20 Td
(Total Time: 3 Hours) Tj
0 -20 Td
(Maximum Marks: 100) Tj
ET

BT
/F2 16 Tf
50 560 Td
(SECTION A - 10 Questions [2 marks each]) Tj
ET

BT
/F1 12 Tf
50 530 Td
(Question A1: What is a computer?) Tj
70 -20 Td
(Answer: A computer is an electronic device that manipulates information or data. It has the ability) Tj
0 -15 Td
(to store, retrieve, and process data. It can be a desktop, laptop, tablet, or smartphone.) Tj
ET

BT
/F1 12 Tf
50 460 Td
(Question A2: Define an operating system.) Tj
70 -20 Td
(Answer: An operating system is system software that manages computer hardware, software) Tj
0 -15 Td
(resources, and provides common services for computer programs. Examples include Windows,) Tj
0 -15 Td
(macOS, Linux, and Android.) Tj
ET

BT
/F1 12 Tf
50 380 Td
(Question A3: What is binary code?) Tj
70 -20 Td
(Answer: Binary code is a system of representing text or computer processor instructions using the) Tj
0 -15 Td
(binary number system with just two values: 0 and 1. It's the fundamental language of computers.) Tj
ET

BT
/F1 12 Tf
50 310 Td
(Question A4: What is the function of RAM?) Tj
70 -20 Td
(Answer: RAM (Random Access Memory) provides space for your computer to read and write data) Tj
0 -15 Td
(that is actively being used, which can be accessed randomly at any time. It's volatile memory.) Tj
ET

BT
/F1 12 Tf
50 240 Td
(Question A5: What is an algorithm?) Tj
70 -20 Td
(Answer: An algorithm is a step-by-step procedure or formula for solving a problem. In computing,) Tj
0 -15 Td
(it's a well-defined set of instructions to perform a specific task or solve a particular problem.) Tj
ET

BT
/F1 12 Tf
50 170 Td
(Question A6: Explain the difference between hardware and software.) Tj
70 -20 Td
(Answer: Hardware refers to the physical components of a computer system that you can touch,) Tj
0 -15 Td
(such as the monitor, keyboard, and processor. Software refers to the programs and applications) Tj
0 -15 Td
(that run on the hardware, providing specific functionality.) Tj
ET

BT
/F1 12 Tf
50 100 Td
(Question A7: What is a compiler?) Tj
70 -20 Td
(Answer: A compiler is a special program that translates code written in a high-level programming) Tj
0 -15 Td
(language into machine code that a computer can execute directly.) Tj
ET
endstream
endobj
7 0 obj
<</Length 2500>>
stream
BT
/F1 12 Tf
50 730 Td
(Question A8: What is a database?) Tj
70 -20 Td
(Answer: A database is an organized collection of structured information or data, typically stored) Tj
0 -15 Td
(electronically in a computer system. Databases are designed for easy data retrieval and management.) Tj
ET

BT
/F1 12 Tf
50 660 Td
(Question A9: What is cloud computing?) Tj
70 -20 Td
(Answer: Cloud computing is the delivery of computing services over the internet (the cloud),) Tj
0 -15 Td
(including servers, storage, databases, networking, software, and analytics. It offers faster) Tj
0 -15 Td
(innovation, flexible resources, and economies of scale.) Tj
ET

BT
/F1 12 Tf
50 590 Td
(Question A10: What is a programming language?) Tj
70 -20 Td
(Answer: A programming language is a formal language comprising a set of instructions that produce) Tj
0 -15 Td
(various kinds of output. Programming languages are used to implement algorithms and create) Tj
0 -15 Td
(software applications. Examples include Python, Java, C++, and JavaScript.) Tj
ET

BT
/F2 16 Tf
50 500 Td
(SECTION B - 8 Questions [5 marks each]) Tj
ET

BT
/F1 12 Tf
50 470 Td
(Question B1: Explain the concept of object-oriented programming.) Tj
70 -20 Td
(Answer: Object-oriented programming (OOP) is a programming paradigm based on the concept of) Tj
0 -15 Td
("objects," which can contain data and code. The data is in the form of fields (attributes), and) Tj
0 -15 Td
(the code is in the form of procedures (methods). OOP features include encapsulation, inheritance,) Tj
0 -15 Td
(polymorphism, and abstraction. This approach helps organize code, making it more reusable,) Tj
0 -15 Td
(flexible, and easier to maintain.) Tj
ET

BT
/F1 12 Tf
50 370 Td
(Question B2: Describe the OSI model and its layers.) Tj
70 -20 Td
(Answer: The OSI (Open Systems Interconnection) model is a conceptual framework used to) Tj
0 -15 Td
(understand network interactions. It consists of seven layers: Physical, Data Link, Network,) Tj
0 -15 Td
(Transport, Session, Presentation, and Application. Each layer serves a specific function in the) Tj
0 -15 Td
(process of transmitting data across a network. This layered approach allows for modular design) Tj
0 -15 Td
(and troubleshooting of network systems and protocols.) Tj
ET

BT
/F1 12 Tf
50 260 Td
(Question B3: Explain the concept of database normalization.) Tj
70 -20 Td
(Answer: Database normalization is the process of structuring a relational database to reduce) Tj
0 -15 Td
(data redundancy and improve data integrity. It involves organizing fields and tables to minimize) Tj
0 -15 Td
(duplicate data and eliminate anomalies. There are several normal forms (1NF, 2NF, 3NF, BCNF, etc.)) Tj
0 -15 Td
(that progressively impose more constraints on the database design, making it more efficient and) Tj
0 -15 Td
(reducing the risk of inconsistencies when updating data.) Tj
ET

BT
/F1 12 Tf
50 150 Td
(Question B4: Describe the concept of recursion in programming.) Tj
70 -20 Td
(Answer: Recursion is a programming technique where a function calls itself to solve a smaller) Tj
0 -15 Td
(instance of the same problem. It consists of a base case (termination condition) and a recursive) Tj
0 -15 Td
(case. Common applications include tree traversals, factorial calculations, and Fibonacci sequences.) Tj
0 -15 Td
(While powerful, recursion can lead to stack overflow errors if not implemented carefully with) Tj
0 -15 Td
(proper termination conditions.) Tj
ET
endstream
endobj
8 0 obj
<</Length 2500>>
stream
BT
/F1 12 Tf
50 730 Td
(Question B5: Explain the differences between HTTP and HTTPS.) Tj
70 -20 Td
(Answer: HTTP (Hypertext Transfer Protocol) and HTTPS (HTTP Secure) are protocols used for) Tj
0 -15 Td
(transmitting data over the web. The key difference is that HTTPS encrypts the data using SSL/TLS,) Tj
0 -15 Td
(providing secure communication, while HTTP transmits data in plaintext. HTTPS uses port 443) Tj
0 -15 Td
(by default, while HTTP uses port 80. HTTPS provides authentication of websites, protects privacy) Tj
0 -15 Td
(and integrity of exchanged data, and is essential for secure transactions like online banking.) Tj
ET

BT
/F1 12 Tf
50 620 Td
(Question B6: Describe the concept of virtualization in computing.) Tj
70 -20 Td
(Answer: Virtualization is the creation of a virtual version of something, such as an operating) Tj
0 -15 Td
(system, server, storage device, or network resources. It allows multiple virtual systems to run on) Tj
0 -15 Td
(a single physical hardware system. Benefits include server consolidation, better resource utilization,) Tj
0 -15 Td
(improved disaster recovery, and easier system migration. Common types include hardware virtualization,) Tj
0 -15 Td
(software virtualization, and desktop virtualization.) Tj
ET

BT
/F1 12 Tf
50 510 Td
(Question B7: Explain Big O notation and why it's important in algorithm analysis.) Tj
70 -20 Td
(Answer: Big O notation is a mathematical notation that describes the limiting behavior of a function) Tj
0 -15 Td
(when the argument tends towards a particular value or infinity. In computing, it's used to classify) Tj
0 -15 Td
(algorithms according to how their run time or space requirements grow as the input size grows.) Tj
0 -15 Td
(Examples include O(1) for constant time, O(log n) for logarithmic time, O(n) for linear time, etc.) Tj
0 -15 Td
(It's important because it helps developers compare algorithms and select the most efficient one.) Tj
ET

BT
/F1 12 Tf
50 400 Td
(Question B8: Describe the concept of distributed computing.) Tj
70 -20 Td
(Answer: Distributed computing is a model where components of a software system are shared among) Tj
0 -15 Td
(multiple computers to improve efficiency and performance. These systems can use multiple CPUs) Tj
0 -15 Td
(in a single machine, or thousands of machines with their processors. Benefits include increased) Tj
0 -15 Td
(performance, reliability, and scalability. Challenges include network latency, fault tolerance,) Tj
0 -15 Td
(and maintaining data consistency across nodes.) Tj
ET

BT
/F2 16 Tf
50 300 Td
(SECTION C - 4 Questions [10 marks each]) Tj
ET

BT
/F1 12 Tf
50 270 Td
(Question C1: Discuss the implications of artificial intelligence on society and ethics.) Tj
70 -20 Td
(Answer: Artificial Intelligence (AI) presents both opportunities and challenges for society and ethics.) Tj
0 -15 Td
(On the positive side, AI can enhance healthcare through better diagnostics, improve education with) Tj
0 -15 Td
(personalized learning, and increase efficiency in various industries. However, it also raises concerns) Tj
0 -15 Td
(about privacy as AI systems collect and analyze vast amounts of personal data. Job displacement is) Tj
0 -15 Td
(another concern as automation may eliminate certain roles. Ethical issues include algorithmic bias,) Tj
0 -15 Td
(where AI systems may perpetuate or amplify existing societal biases. Autonomy and accountability) Tj
0 -15 Td
(questions arise regarding who is responsible when AI makes harmful decisions. There are also concerns) Tj
0 -15 Td
(about the potential for surveillance and control. Addressing these challenges requires multidisciplinary) Tj
0 -15 Td
(approaches involving technologists, ethicists, policymakers, and the broader public to ensure AI) Tj
0 -15 Td
(development aligns with human values and benefits society as a whole.) Tj
ET

BT
/F1 12 Tf
50 90 Td
(Question C2: Analyze the evolution of cybersecurity threats and defenses in the digital age.) Tj
70 -20 Td
(Answer: Cybersecurity threats have evolved significantly in the digital age, transitioning from) Tj
0 -15 Td
(simple viruses created by hobbyists to sophisticated attacks orchestrated by nation-states and) Tj
0 -15 Td
(organized criminal groups. Early threats like file viruses and worms have evolved into advanced) Tj
0 -15 Td
(persistent threats (APTs), ransomware, social engineering attacks, and zero-day exploits.) Tj
ET
endstream
endobj
xref
0 9
0000000000 65535 f
0000000010 00000 n
0000000056 00000 n
0000000117 00000 n
0000000286 00000 n
0000000455 00000 n
0000000624 00000 n
0000003176 00000 n
0000005728 00000 n
trailer
<</Size 9/Root 1 0 R>>
startxref
8280
%%EOF`);
    console.log("Created multi-page sample PDF at", samplePdfPath);
  }
  app2.post("/api/sample-data", isAuthenticated, hasRole(["admin"]), async (req, res, next) => {
    try {
      const courses2 = await storage.listCourses();
      if (courses2.length > 0) {
        return res.status(200).json({ message: "Sample data already exists" });
      }
      const course = await storage.createCourse({
        department: "Computer Science",
        name: "Introduction to Computing",
        code: "CS101",
        description: "Basic concepts of computer systems"
      });
      const exam = await storage.createExam({
        courseId: course.id,
        title: "Midterm Exam",
        examDate: /* @__PURE__ */ new Date(),
        duration: 120,
        totalMarks: 100,
        instructorId: req.user?.id ?? 0,
        description: "First midterm exam",
        venue: "Room 101"
      });
      await storage.createQuestion({
        examId: exam.id,
        questionNumber: 1,
        questionText: "Explain the basic components of a computer system.",
        marks: 10
      });
      await storage.createQuestion({
        examId: exam.id,
        questionNumber: 2,
        questionText: "What is an algorithm? Provide an example.",
        marks: 10
      });
      await storage.createQuestion({
        examId: exam.id,
        questionNumber: 3,
        questionText: "Describe the difference between RAM and ROM.",
        marks: 10
      });
      let student;
      const students = await storage.listUsers("student");
      if (students.length > 0) {
        student = students[0];
      } else {
        student = await storage.createUser({
          username: "john.student",
          password: await hashPassword2("password"),
          fullName: "John Student",
          email: "john@example.com",
          role: "student",
          department: "Computer Science",
          studentId: "CS2023001"
        });
      }
      const enrollment = await storage.createEnrollment({
        courseId: course.id,
        userId: student.id,
        academicYear: "2024",
        semester: "Spring"
      });
      const answerSheet = {
        studentId: student.id,
        examId: exam.id,
        filePath: req.file?.path ?? ""
      };
      res.status(201).json({
        message: "Sample data created successfully",
        course,
        exam,
        student: { id: student.id, fullName: student.fullName },
        enrollment,
        answerSheet
      });
    } catch (err) {
      next(err);
    }
  });
  app2.use((err, req, res, next) => {
    if (err instanceof ZodError) {
      const validationError = fromZodError(err);
      return res.status(400).json({ message: validationError.message });
    }
    next(err);
  });
  app2.get("/api/users", isAuthenticated, hasRole(["admin", "staff"]), async (req, res, next) => {
    try {
      const role = req.query.role;
      const users2 = await storage.listUsers(role);
      const userResponse = users2.map((user) => {
        const { password, ...userWithoutPassword } = user;
        return userWithoutPassword;
      });
      res.json(userResponse);
    } catch (err) {
      next(err);
    }
  });
  app2.get("/api/users/:id", requireAuth, async (req, res, next) => {
    try {
      const id = parseInt(req.params.id);
      const user = await storage.getUser(id);
      if (!user) {
        return res.status(404).json({ message: "User not found" });
      }
      if (req.user.id !== id && !["admin", "staff"].includes(req.user.role)) {
        return res.status(403).json({ message: "Forbidden" });
      }
      const { password, ...userWithoutPassword } = user;
      res.json(userWithoutPassword);
    } catch (err) {
      next(err);
    }
  });
  app2.put("/api/users/:id", isAuthenticated, hasRole(["admin"]), async (req, res, next) => {
    try {
      const id = parseInt(req.params.id);
      const updates = req.body;
      if (updates.password) {
        delete updates.password;
      }
      const updatedUser = await storage.updateUser(id, updates);
      if (!updatedUser) {
        return res.status(404).json({ message: "User not found" });
      }
      const { password, ...userWithoutPassword } = updatedUser;
      res.json(userWithoutPassword);
    } catch (err) {
      next(err);
    }
  });
  app2.delete("/api/users/:id", isAuthenticated, hasRole(["admin"]), async (req, res, next) => {
    try {
      const id = parseInt(req.params.id);
      await storage.deleteUser(id);
      res.sendStatus(204);
    } catch (err) {
      next(err);
    }
  });
  app2.get("/api/courses", isAuthenticated, async (req, res, next) => {
    try {
      const courses2 = await storage.listCourses();
      res.json(courses2);
    } catch (err) {
      next(err);
    }
  });
  app2.get("/api/courses/:id", isAuthenticated, async (req, res, next) => {
    try {
      const id = parseInt(req.params.id);
      const course = await storage.getCourse(id);
      if (!course) {
        return res.status(404).json({ message: "Course not found" });
      }
      res.json(course);
    } catch (err) {
      next(err);
    }
  });
  app2.post("/api/courses", isAuthenticated, hasRole(["admin", "staff"]), async (req, res, next) => {
    try {
      const course = await storage.createCourse(req.body);
      res.status(201).json(course);
    } catch (err) {
      next(err);
    }
  });
  app2.put("/api/courses/:id", isAuthenticated, hasRole(["admin", "staff"]), async (req, res, next) => {
    try {
      const id = parseInt(req.params.id);
      const updatedCourse = await storage.updateCourse(id, req.body);
      if (!updatedCourse) {
        return res.status(404).json({ message: "Course not found" });
      }
      res.json(updatedCourse);
    } catch (err) {
      next(err);
    }
  });
  app2.delete("/api/courses/:id", isAuthenticated, hasRole(["admin"]), async (req, res, next) => {
    try {
      const id = parseInt(req.params.id);
      await storage.deleteCourse(id);
      res.sendStatus(204);
    } catch (err) {
      next(err);
    }
  });
  app2.post("/api/enrollments", isAuthenticated, hasRole(["admin", "staff"]), async (req, res, next) => {
    try {
      const enrollment = await storage.createEnrollment(req.body);
      res.status(201).json(enrollment);
    } catch (err) {
      next(err);
    }
  });
  app2.delete("/api/enrollments/:id", isAuthenticated, hasRole(["admin", "staff"]), async (req, res, next) => {
    try {
      const id = parseInt(req.params.id);
      await storage.deleteEnrollment(id);
      res.sendStatus(204);
    } catch (err) {
      next(err);
    }
  });
  app2.get("/api/courses/:id/students", isAuthenticated, async (req, res, next) => {
    try {
      const courseId = parseInt(req.params.id);
      const students = await storage.getStudentsByCoursesId(courseId);
      const studentsResponse = students.map((student) => {
        const { password, ...studentWithoutPassword } = student;
        return studentWithoutPassword;
      });
      res.json(studentsResponse);
    } catch (err) {
      next(err);
    }
  });
  app2.get("/api/students/:id/courses", isAuthenticated, async (req, res, next) => {
    try {
      const studentId = parseInt(req.params.id);
      if (req.user.id !== studentId && !["admin", "staff", "instructor", "second_instructor"].includes(req.user.role)) {
        return res.status(403).json({ message: "Forbidden" });
      }
      const courses2 = await storage.getCoursesByStudentId(studentId);
      res.json(courses2);
    } catch (err) {
      next(err);
    }
  });
  app2.get("/api/exams", isAuthenticated, async (req, res, next) => {
    try {
      const user = req.user;
      let exams2;
      if (user.role === "student") {
        exams2 = await storage.getExamsByStudentId(user.id);
      } else if (user.role === "instructor" || user.role === "second_instructor") {
        exams2 = await storage.getExamsByInstructorId(user.id);
      } else {
        exams2 = await storage.listExams();
      }
      res.json(exams2);
    } catch (err) {
      next(err);
    }
  });
  app2.get("/api/exams/:id", isAuthenticated, async (req, res, next) => {
    try {
      const id = parseInt(req.params.id);
      const exam = await storage.getExam(id);
      if (!exam) {
        return res.status(404).json({ message: "Exam not found" });
      }
      const user = req.user;
      if (user.role === "student") {
        const studentCourses = await storage.getCoursesByStudentId(user.id);
        const hasAccess = studentCourses.some((course) => course.id === exam.courseId);
        if (!hasAccess) {
          return res.status(403).json({ message: "Forbidden" });
        }
      } else if (user.role === "instructor" || user.role === "second_instructor") {
        if (exam.instructorId !== user.id && exam.secondInstructorId !== user.id) {
          return res.status(403).json({ message: "Forbidden" });
        }
      }
      res.json(exam);
    } catch (err) {
      next(err);
    }
  });
  app2.post("/api/exams", isAuthenticated, hasRole(["admin", "staff", "instructor"]), async (req, res, next) => {
    try {
      const exam = await storage.createExam(req.body);
      res.status(201).json(exam);
    } catch (err) {
      next(err);
    }
  });
  app2.put("/api/exams/:id", isAuthenticated, hasRole(["admin", "staff", "instructor"]), async (req, res, next) => {
    try {
      const id = parseInt(req.params.id);
      const exam = await storage.getExam(id);
      if (!exam) {
        return res.status(404).json({ message: "Exam not found" });
      }
      const user = req.user;
      if (user.role === "instructor" && exam.instructorId !== user.id) {
        return res.status(403).json({ message: "Forbidden" });
      }
      const updatedExam = await storage.updateExam(id, req.body);
      res.json(updatedExam);
    } catch (err) {
      next(err);
    }
  });
  app2.delete("/api/exams/:id", isAuthenticated, hasRole(["admin", "staff"]), async (req, res, next) => {
    try {
      const id = parseInt(req.params.id);
      await storage.deleteExam(id);
      res.sendStatus(204);
    } catch (err) {
      next(err);
    }
  });
  app2.post("/api/questions", isAuthenticated, hasRole(["admin", "staff", "instructor"]), async (req, res, next) => {
    try {
      const question = await storage.createQuestion(req.body);
      res.status(201).json(question);
    } catch (err) {
      next(err);
    }
  });
  app2.get("/api/exams/:id/questions", isAuthenticated, async (req, res, next) => {
    try {
      const examId = parseInt(req.params.id);
      const exam = await storage.getExam(examId);
      if (!exam) {
        return res.status(404).json({ message: "Exam not found" });
      }
      const user = req.user;
      if (user.role === "student") {
        const studentCourses = await storage.getCoursesByStudentId(user.id);
        const hasAccess = studentCourses.some((course) => course.id === exam.courseId);
        if (!hasAccess) {
          return res.status(403).json({ message: "Forbidden" });
        }
      } else if (user.role === "instructor" || user.role === "second_instructor") {
        if (exam.instructorId !== user.id && exam.secondInstructorId !== user.id) {
          return res.status(403).json({ message: "Forbidden" });
        }
      }
      const questions2 = await storage.getQuestionsByExamId(examId);
      res.json(questions2);
    } catch (err) {
      next(err);
    }
  });
  app2.post("/api/answer-sheets", isAuthenticated, upload.single("file"), async (req, res, next) => {
    try {
      if (!req.file) {
        return res.status(400).json({ message: "No file uploaded" });
      }
      const { examId, studentId } = req.body;
      const answerSheet = {
        studentId: parseInt(studentId),
        examId: parseInt(examId),
        filePath: req.file.path
      };
      res.status(201).json(answerSheet);
    } catch (err) {
      next(err);
    }
  });
  app2.get("/api/answer-sheets/:id", isAuthenticated, async (req, res, next) => {
    try {
      const id = parseInt(req.params.id);
      const answerSheet = await storage.getAnswerSheet(id);
      if (!answerSheet) {
        return res.status(404).json({ message: "Answer sheet not found" });
      }
      const user = req.user;
      if (user.role === "student") {
        if (answerSheet.studentId !== user.id) {
          return res.status(403).json({ message: "Forbidden" });
        }
      } else if (user.role === "instructor" || user.role === "second_instructor") {
        const exam = await storage.getExam(answerSheet.examId);
        if (!exam || exam.instructorId !== user.id && exam.secondInstructorId !== user.id) {
          return res.status(403).json({ message: "Forbidden" });
        }
      }
      res.json(answerSheet);
    } catch (err) {
      next(err);
    }
  });
  app2.get("/api/exams/:id/answer-sheets", isAuthenticated, hasRole(["admin", "staff", "instructor", "second_instructor"]), async (req, res, next) => {
    try {
      const examId = parseInt(req.params.id);
      const exam = await storage.getExam(examId);
      if (!exam) {
        return res.status(404).json({ message: "Exam not found" });
      }
      const user = req.user;
      if (user.role === "instructor" || user.role === "second_instructor") {
        if (exam.instructorId !== user.id && exam.secondInstructorId !== user.id) {
          return res.status(403).json({ message: "Forbidden" });
        }
      }
      const answerSheets2 = await storage.getAnswerSheetsByExamId(examId);
      res.json(answerSheets2);
    } catch (err) {
      next(err);
    }
  });
  app2.get("/api/students/:id/answer-sheets", isAuthenticated, async (req, res, next) => {
    try {
      const studentId = parseInt(req.params.id);
      const user = req.user;
      if (user.role === "student" && user.id !== studentId) {
        return res.status(403).json({ message: "Forbidden" });
      }
      const answerSheets2 = await storage.getAnswerSheetsByStudentId(studentId);
      res.json(answerSheets2);
    } catch (err) {
      next(err);
    }
  });
  app2.put("/api/answer-sheets/:id", isAuthenticated, hasRole(["instructor", "second_instructor"]), async (req, res, next) => {
    try {
      const id = parseInt(req.params.id);
      const answerSheet = await storage.getAnswerSheet(id);
      if (!answerSheet) {
        return res.status(404).json({ message: "Answer sheet not found" });
      }
      const exam = await storage.getExam(answerSheet.examId);
      const user = req.user;
      if (!exam || exam.instructorId !== user.id && exam.secondInstructorId !== user.id) {
        return res.status(403).json({ message: "Forbidden" });
      }
      const updates = req.body;
      if (!answerSheet.gradedBy) {
        updates.gradedBy = user.id;
        updates.gradedAt = /* @__PURE__ */ new Date();
      }
      if (user.role === "second_instructor" && exam.secondInstructorId === user.id) {
        updates.reviewedBy = user.id;
        updates.reviewedAt = /* @__PURE__ */ new Date();
        updates.status = "reviewed";
      } else {
        updates.status = "completed";
      }
      const updatedAnswerSheet = await storage.updateAnswerSheet(id, updates);
      res.json(updatedAnswerSheet);
    } catch (err) {
      next(err);
    }
  });
  app2.post("/api/question-grades", isAuthenticated, hasRole(["instructor", "second_instructor"]), async (req, res, next) => {
    try {
      const { answerSheetId, questionId, score, feedback } = req.body;
      const answerSheet = await storage.getAnswerSheet(parseInt(answerSheetId));
      if (!answerSheet) {
        return res.status(404).json({ message: "Answer sheet not found" });
      }
      const exam = await storage.getExam(answerSheet.examId);
      const user = req.user;
      if (!exam || exam.instructorId !== user.id && exam.secondInstructorId !== user.id) {
        return res.status(403).json({ message: "Forbidden" });
      }
      const questionGrade = await storage.createQuestionGrade({
        answerSheetId: parseInt(answerSheetId),
        questionId: parseInt(questionId),
        score: parseInt(score),
        feedback
      });
      res.status(201).json(questionGrade);
    } catch (err) {
      next(err);
    }
  });
  app2.get("/api/answer-sheets/:id/question-grades", isAuthenticated, async (req, res, next) => {
    try {
      const answerSheetId = parseInt(req.params.id);
      const answerSheet = await storage.getAnswerSheet(answerSheetId);
      if (!answerSheet) {
        return res.status(404).json({ message: "Answer sheet not found" });
      }
      const user = req.user;
      if (user.role === "student") {
        if (answerSheet.studentId !== user.id) {
          return res.status(403).json({ message: "Forbidden" });
        }
      } else if (user.role === "instructor" || user.role === "second_instructor") {
        const exam = await storage.getExam(answerSheet.examId);
        if (!exam || exam.instructorId !== user.id && exam.secondInstructorId !== user.id) {
          return res.status(403).json({ message: "Forbidden" });
        }
      }
      const questionGrades2 = await storage.getQuestionGradesByAnswerSheetId(answerSheetId);
      res.json(questionGrades2);
    } catch (err) {
      next(err);
    }
  });
  app2.get("/api/instructors/pending-grading", isAuthenticated, hasRole(["instructor", "second_instructor"]), async (req, res, next) => {
    try {
      const pendingGrading = await storage.getPendingGradingByInstructorId(req.user.id);
      res.json(pendingGrading);
    } catch (err) {
      next(err);
    }
  });
  app2.get("/uploads/:filename", isAuthenticated, async (req, res, next) => {
    try {
      const filename = req.params.filename;
      const filePath = path.join(uploadDir, filename);
      try {
        await util.promisify(fs.access)(filePath, fs.constants.F_OK);
      } catch (err) {
        return res.status(404).json({ message: "File not found" });
      }
      const answerSheet = (await db.select().from(answerSheets).where(eq2(answerSheets.filePath, filePath)))[0];
      if (!answerSheet) {
        return res.status(404).json({ message: "Answer sheet not found" });
      }
      const user = req.user;
      if (user.role === "student") {
        if (answerSheet.studentId !== user.id) {
          return res.status(403).json({ message: "Forbidden" });
        }
      } else if (user.role === "instructor" || user.role === "second_instructor") {
        const exam = await storage.getExam(answerSheet.examId);
        if (!exam || exam.instructorId !== user.id && exam.secondInstructorId !== user.id) {
          return res.status(403).json({ message: "Forbidden" });
        }
      }
      res.sendFile(filePath);
    } catch (err) {
      next(err);
    }
  });
  const httpServer = createServer(app2);
  return httpServer;
}

// server/vite.ts
import express from "express";
import fs2 from "fs";
import path3 from "path";
import { createServer as createViteServer, createLogger } from "vite";

// vite.config.ts
import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";
import themePlugin from "@replit/vite-plugin-shadcn-theme-json";
import path2 from "path";
import runtimeErrorOverlay from "@replit/vite-plugin-runtime-error-modal";
var vite_config_default = defineConfig({
  plugins: [
    react(),
    runtimeErrorOverlay(),
    themePlugin(),
    ...process.env.NODE_ENV !== "production" && process.env.REPL_ID !== void 0 ? [
      await import("@replit/vite-plugin-cartographer").then(
        (m) => m.cartographer()
      )
    ] : []
  ],
  resolve: {
    alias: {
      "@": path2.resolve(import.meta.dirname, "client", "src"),
      "@shared": path2.resolve(import.meta.dirname, "shared"),
      "@assets": path2.resolve(import.meta.dirname, "attached_assets")
    }
  },
  optimizeDeps: {
    include: [
      "@tensorflow/tfjs",
      "@tensorflow/tfjs-core",
      "@tensorflow/tfjs-converter",
      "@tensorflow-models/coco-ssd",
      "@tensorflow-models/facemesh",
      "@tensorflow-models/blazeface",
      "seedrandom"
    ],
    exclude: []
  },
  root: path2.resolve(import.meta.dirname, "client"),
  build: {
    outDir: path2.resolve(import.meta.dirname, "dist/public"),
    emptyOutDir: true,
    commonjsOptions: {
      include: [/node_modules/],
      transformMixedEsModules: true
    }
  }
});

// server/vite.ts
import { nanoid } from "nanoid";
var viteLogger = createLogger();
function log(message, source = "express") {
  const formattedTime = (/* @__PURE__ */ new Date()).toLocaleTimeString("en-US", {
    hour: "numeric",
    minute: "2-digit",
    second: "2-digit",
    hour12: true
  });
  console.log(`${formattedTime} [${source}] ${message}`);
}
async function setupVite(app2, server) {
  const serverOptions = {
    middlewareMode: true,
    hmr: { server },
    allowedHosts: true
  };
  const vite = await createViteServer({
    ...vite_config_default,
    configFile: false,
    customLogger: {
      ...viteLogger,
      error: (msg, options) => {
        viteLogger.error(msg, options);
        process.exit(1);
      }
    },
    server: serverOptions,
    appType: "custom"
  });
  app2.use(vite.middlewares);
  app2.use("*", async (req, res, next) => {
    const url = req.originalUrl;
    try {
      const clientTemplate = path3.resolve(
        import.meta.dirname,
        "..",
        "client",
        "index.html"
      );
      let template = await fs2.promises.readFile(clientTemplate, "utf-8");
      template = template.replace(
        `src="/src/main.tsx"`,
        `src="/src/main.tsx?v=${nanoid()}"`
      );
      const page = await vite.transformIndexHtml(url, template);
      res.status(200).set({ "Content-Type": "text/html" }).end(page);
    } catch (e) {
      vite.ssrFixStacktrace(e);
      next(e);
    }
  });
}
function serveStatic(app2) {
  const distPath = path3.resolve(import.meta.dirname, "public");
  if (!fs2.existsSync(distPath)) {
    throw new Error(
      `Could not find the build directory: ${distPath}, make sure to build the client first`
    );
  }
  app2.use(express.static(distPath));
  app2.use("*", (_req, res) => {
    res.sendFile(path3.resolve(distPath, "index.html"));
  });
}

// server/index.ts
var app = express2();
app.use(express2.json());
app.use(express2.urlencoded({ extended: false }));
app.use((req, res, next) => {
  const start = Date.now();
  const path4 = req.path;
  let capturedJsonResponse = void 0;
  const originalResJson = res.json;
  res.json = function(bodyJson, ...args) {
    capturedJsonResponse = bodyJson;
    return originalResJson.apply(res, [bodyJson, ...args]);
  };
  res.on("finish", () => {
    const duration = Date.now() - start;
    if (path4.startsWith("/api")) {
      let logLine = `${req.method} ${path4} ${res.statusCode} in ${duration}ms`;
      if (capturedJsonResponse) {
        logLine += ` :: ${JSON.stringify(capturedJsonResponse)}`;
      }
      if (logLine.length > 80) {
        logLine = logLine.slice(0, 79) + "\u2026";
      }
      log(logLine);
    }
  });
  next();
});
(async () => {
  try {
    const server = await registerRoutes(app);
    app.use((err, _req, res, _next) => {
      const status = err.status || err.statusCode || 500;
      const message = err.message || "Internal Server Error";
      res.status(status).json({ message });
      throw err;
    });
    if (app.get("env") === "development") {
      await setupVite(app, server);
    } else {
      serveStatic(app);
    }
    const port = 5e3;
    server.on("error", (error) => {
      if (error.code === "EADDRINUSE") {
        log(`Port ${port} is in use, trying port ${port + 1}`);
        server.listen(port + 1, "localhost", () => {
          log(`serving on port ${port + 1}`);
        });
      } else {
        log(`Server error: ${error.message}`);
        process.exit(1);
      }
    });
    server.listen(port, "localhost", () => {
      log(`serving on port ${port}`);
    });
  } catch (error) {
    log(`Failed to start server: ${error}`);
    process.exit(1);
  }
})();
