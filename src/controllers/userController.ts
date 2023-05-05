import { prisma } from "database/prismaClient";
import { Request, Response } from "express";
import bcrypt from "bcrypt";
import jwt from "jsonwebtoken";
import z from "zod";

const registerSchema = z.object({
	username: z
		.string()
		.nonempty("Campo username é obrigatório.")
		.regex(new RegExp(/^[a-zA-Z\s]+$/), {
			message: "Não é permitido uso de caracteres especiais ou numeros.",
		})
		.min(3, { message: "Nome de usuário deve ter no mínimo 3 caracteres." })
		.max(20, {
			message: "O nome de usuário pode ter no maximo 20 caracteres.",
		}),
	email: z
		.string()
		.email({ message: "Email inválido." })
		.nonempty("Campo email é obrigatório."),
	password: z
		.string()
		.nonempty("Campo senha é obrigatório.")
		.min(8, { message: "A senha deve ter no mínimo 8 caracteres." }),
});

const loginSchema = z.object({
	email: z.string().email(),
	password: z.string().min(8),
});

function generateToken(user: { id: number }): Promise<string> {
	const payload = { userId: user.id };
	return new Promise((resolve, reject) => {
		jwt.sign(
			payload,
			process.env.JWT_SECRET || "secret",
			{ expiresIn: "1d" },
			(err, token) => {
				if (err) {
					reject(err);
				} else {
					resolve(token);
				}
			}
		);
	});
}

export async function register(req: Request, res: Response): Promise<Object> {
	try {
		let { username, email, password } = registerSchema.parse(req.body);

		const existingUser = await prisma.user.findUnique({ where: { email } });

		if (existingUser) {
			return res.status(401).json({ message: "Email já cadastrado" });
		}

		const passwordHash = await bcrypt.hash(password, 10);
		password = passwordHash;
		const user = await prisma.user.create({
			data: {
				username,
				email,
				password,
			},
		});

		const token = await generateToken(user);

		return res.status(201).json({ token });
	} catch (err) {
		console.error(err);
		return res.status(400).json({ message: err.errors[0].message });
	}
}

export async function login(req: Request, res: Response): Promise<void> {
	try {
		const { email, password } = loginSchema.parse(req.body);

		const user = await prisma.user.findUnique({ where: { email } });

		if (!user) {
			res.status(401).json({ message: "Esta conta não existe." });
		}

		const isValidPassword = await bcrypt.compare(password, user.password);

		if (!isValidPassword) {
			res.status(401).json({ message: "Email ou senha incorretos." });
		}

		const token = await generateToken(user);

		res.status(200).json({ token });
	} catch (err) {
		console.error(err);
		res.status(400).json({ message: "Email ou senha incorretos." });
	}
}
export async function user(req: Request, res: Response) {
	const token = req.headers.authorization?.split(" ")[1];
	try {
		const decoded = jwt.verify(token, process.env.JWT_SECRET);

		// const user = await prisma.user.findUnique({
		// 	where: { id: decoded.id },
		// });
		// if (!user) {
		// 	throw new Error("User not found");
		// }
		res.json({ username: user.username });
	} catch (err) {
		console.error(err.message);
		res.status(401).json({ message: "Unauthorized" });
	}
}
