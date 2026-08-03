import { ZodError } from "zod";

export const validate = (schema) => {
  return (req,res,next) => {
    try{
      req.body = schema.parse(req.body);

      next();
    } catch(error) {
      if (error instanceof ZodError) {
        return res.status(400).json({
          success: false,
          message: "Validation failed",
          errors: error.issues.map((issue)=>({
            field: issue.path.join("."),
            message: issue.message,
          })),
        });
      }
      next(error)
    }
  };
};