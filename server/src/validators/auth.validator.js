import { z } from "zod";

export const registerSchema= z.object({
  name: z
  .string()
  .trim()
  .min(3,"Name must be at least 3 characters")
  .max(50, "Name is too long"),

email: z
.email("Invalid email address")
.trim()
.toLowerCase(),

password: z
.string()
.min(8, "Password must be at least 8 characters")
.max(100)
});

export const loginSchema = z.object({
  email: z
    .string()
    .trim()
    .toLowerCase()
    .email("Invalid email address"),

  password: z
    .string()
    .min(1, "Password is required"),
});