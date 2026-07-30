export const getHealth = (req, res) => {
  res.status(200).json({
    success: true,
    message: "SecureShare API is running",
    version: "1.0.0",
  });
};