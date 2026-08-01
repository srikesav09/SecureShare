export const register = async (requestAnimationFrame,res) => {
  res.status(200).json({
    success: true,
    message: "Register controller is working"
  });
};