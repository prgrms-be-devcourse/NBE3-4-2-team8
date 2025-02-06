"use client";
import React, { useState, KeyboardEvent } from "react";
import { useRouter } from "next/navigation";
import { SearchType } from "@/types/book"; // types/book.ts에 정의된 SearchType 임포트

const searchOptions = [
    { label: "제목", value: SearchType.TITLE },
    { label: "저자", value: SearchType.AUTHOR },
    { label: "ISBN13", value: SearchType.ISBN13 },
    { label: "출판사", value: SearchType.PUBLISHER },
];

export default function NavBar() {
    const router = useRouter();
    const [searchText, setSearchText] = useState("");
    const [selectedSearchType, setSelectedSearchType] = useState<SearchType>(SearchType.TITLE);

    const handleSearch = () => {
        if (!searchText.trim()) return;
        router.push(
            `/search?keyword=${encodeURIComponent(searchText)}&searchType=${selectedSearchType}`
        );
        setSearchText("");
    };

    const handleKeyDown = (e: KeyboardEvent<HTMLInputElement>) => {
        if (e.key === "Enter") {
            handleSearch();
        }
    };

    return (
        <header className="bg-white shadow">
            <div className="max-w-7xl mx-auto px-4">
                <div className="flex items-center justify-between h-16">
                    {/* 로고 영역 */}
                    <div
                        className="text-2xl font-bold text-gray-800 cursor-pointer"
                        onClick={() => router.push("/")}
                    >
                        THE BOOK
                    </div>

                    {/* 검색 영역 */}
                    <div className="flex-1 max-w-2xl mx-10 flex items-center">
                        <div className="flex w-full max-w-2xl">
                            <select
                                value={selectedSearchType}
                                onChange={(e) =>
                                    setSelectedSearchType(e.target.value as SearchType)
                                }
                                className="px-3 py-2 border border-gray-300 bg-gray-50 text-gray-700 rounded-l-md focus:outline-none focus:ring-2 focus:ring-blue-500 text-sm"
                            >
                                {searchOptions.map((option) => (
                                    <option key={option.value} value={option.value}>
                                        {option.label}
                                    </option>
                                ))}
                            </select>
                            <input
                                type="text"
                                placeholder="검색어를 입력하세요"
                                value={searchText}
                                onChange={(e) => setSearchText(e.target.value)}
                                onKeyDown={handleKeyDown}
                                className="w-full px-3 py-2 border-t border-b border-gray-300 bg-gray-50 text-gray-700 focus:outline-none focus:ring-2 focus:ring-blue-500 text-sm"
                            />
                            <button
                                onClick={handleSearch}
                                className="px-4 py-2 border border-gray-300 bg-white text-blue-500 rounded-r-md hover:bg-gray-100 transition-colors flex items-center justify-center"
                            >
                                {/* 돋보기 아이콘 */}
                                🔍
                            </button>
                        </div>
                    </div>


                    {/* 우측 네비게이션 */}
                    <nav className="flex gap-6 text-sm text-gray-700">
                        <span className="cursor-pointer hover:text-blue-500 transition-colors">로그인</span>
                        <span className="cursor-pointer hover:text-blue-500 transition-colors">장바구니</span>
                        <span className="cursor-pointer hover:text-blue-500 transition-colors">고객센터</span>
                    </nav>
                </div>
            </div>
        </header>
    );
}
