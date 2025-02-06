import { NextResponse } from "next/server";

export const POST = async (req: Request) => {
    console.log("-----------------------------------------------");
    console.log(`api/my/route.ts - Post DeliveryInformation `);
    console.log("-----------------------------------------------");
  
    try {
      const requestBody = await req.json(); // 🔹 요청 데이터 가져오기
      console.log("Received request body:", requestBody);
  
      const response = await fetch(`http://localhost:8080/my/deliveryInformation`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(requestBody),
      });
  
      console.log("Backend response status:", response.status);
      console.log("Backend response headers:", response.headers);
      

        // 🔹 백엔드 응답을 그대로 반환
        return new Response(response.body, {
            status: response.status,
            headers: response.headers,
        });
    } catch (error) {
      console.error("Error processing POST request:", error);
      return new Response(JSON.stringify({ error: "Failed to process request" }), {
        status: 500,
        headers: { "Content-Type": "application/json" },
    });
    }
  };
  
 