import express from "express";
import { router } from "./routes/routes";
import cors from "cors";

const app = express();
app.use(cors());

app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(router);

app.listen(3001, () => console.log("Server is running on PORT 3001"));
