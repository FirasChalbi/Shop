import axios from "axios";

const BASE_URL = "http://localhost:4000/api/";
const TOKEN = "";

export const publicRequest = axios.create({
    baseUrl: BASE_URL,
});

export const userRequest = axios.create({
    baseUrl: BASE_URL,
    header:{token:`Bearer ${TOKEN}`}
});

