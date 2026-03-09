import { GoogleGenerativeAI } from "@google/generative-ai";
import * as dotenv from "dotenv";

dotenv.config();

async function testGemini() {
    const apiKey = process.env.GEMINI_API_KEY;
    if (!apiKey) {
        console.error("GEMINI_API_KEY is missing in .env");
        process.exit(1);
    }

    console.log("Testing Gemini API with key:", apiKey.substring(0, 5) + "...");
    const genAI = new GoogleGenerativeAI(apiKey);
    const model = genAI.getGenerativeModel({ model: "gemini-flash-latest" });

    try {
        const result = await model.generateContent("Say 'Gemini is working'");
        console.log("Response:", result.response.text());
        console.log("API is working correctly!");
    } catch (error) {
        console.error("Gemini API Error:", error);
    }
}

testGemini();
