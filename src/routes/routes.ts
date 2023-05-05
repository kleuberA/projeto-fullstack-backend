import { login, register, user } from "controllers/userController";
import { Router } from "express";

const router = Router();

router.post("/register", register);
router.post("/login", login);
router.get("/user", user);

export { router };
