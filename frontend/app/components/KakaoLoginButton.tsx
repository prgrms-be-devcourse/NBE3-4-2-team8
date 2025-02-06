'use client';

import { useRouter } from 'next/navigation';

export default function KakaoLoginButton() {
  const router = useRouter();

  const handleLogin = () => {
    router.push('http://localhost:8080/oauth2/authorization/kakao');
  };

  return (
    <button
      onClick={handleLogin}
      className="flex items-center gap-2 bg-white hover:bg-gray-200 px-4 py-2 rounded text-black font-medium border border-black"
    >
      카카오로 시작하기
    </button>
  );
}
