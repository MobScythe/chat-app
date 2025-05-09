import express from "express";
import {
  register,
  login,
  logout,
  updateProfile,
  checkAuth,
} from "../controllers/auth.controller.js";
import { protectRoute } from "../middleware/auth.middleware.js";

const router = express.Router();

router.post("/register", register);
router.post("/login", login);
router.post("/logout", logout);

router.put("/update-profile", protectRoute, updateProfile);
router.put("/update-profilePic", protectRoute, updateProfile);
router.delete("/delete-profilePic", protectRoute, updateProfile);

router.get("/check", protectRoute, checkAuth);

export default router;
