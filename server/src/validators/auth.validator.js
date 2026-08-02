import { z } from "zod";

export const regiterSchema= z.object({
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