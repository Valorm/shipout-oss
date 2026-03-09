import React from 'react';

export const Logo = ({ className = "w-7 h-7" }: { className?: string }) => {
    return (
        <div className={className}>
            <svg viewBox="0 0 500 500" width="100%" height="100%" xmlns="http://www.w3.org/2000/svg">
                <defs>
                    <style>
                        {`
              /* Smooth throbbing animation for the core dot */
              .center-dot {
                transform-origin: 250px 250px;
                animation: throb 1.2s ease-in-out infinite;
              }
              @keyframes throb {
                0%, 100% { transform: scale(0.9); }
                50% { transform: scale(1.15); }
              }
            `}
                    </style>

                    {/* Sketch & Ink Bleed Filter for the Drawing */}
                    <filter id="ink-bleed" x="-20%" y="-20%" width="140%" height="140%">
                        {/* Generate high-frequency noise for rough path edges */}
                        <feTurbulence type="fractalNoise" baseFrequency="0.06" numOctaves="3" result="noise" />
                        {/* Displace the drawing paths using the noise */}
                        <feDisplacementMap in="SourceGraphic" in2="noise" scale="2.5" xChannelSelector="R" yChannelSelector="G" result="displaced" />
                        {/* Add a slight blur to simulate ink bleeding */}
                        <feGaussianBlur in="displaced" stdDeviation="0.3" result="blurred" />
                        {/* Darken the blurred result to make the ink look bold and embedded */}
                        <feComponentTransfer in="blurred" result="darkened">
                            <feFuncA type="linear" slope="1.4" />
                        </feComponentTransfer>
                    </filter>
                </defs>

                {/* The Hand-Drawn Sketch */}
                {/* Slight rotation is applied so it feels natural and imperfect */}
                <g transform="rotate(-2, 250, 250)" filter="url(#ink-bleed)" fill="none" stroke="currentColor" strokeLinecap="round" strokeLinejoin="round">

                    {/* VERTICAL LINE (2 overlapping wobbly strokes) */}
                    <path d="M 248 80 Q 254 160 249 250 T 253 420" strokeWidth="4.5" opacity="0.85" />
                    <path d="M 251 85 Q 246 170 251 250 T 250 415" strokeWidth="3.5" opacity="0.75" />

                    {/* LEFT DASHES */}
                    {/* Dash 1 */}
                    <path d="M 88 252 Q 110 249 132 250" strokeWidth="5" opacity="0.9" />
                    <path d="M 90 250 Q 112 251 130 248" strokeWidth="3" opacity="0.8" />
                    {/* Dash 2 */}
                    <path d="M 148 248 Q 165 251 184 249" strokeWidth="4.5" opacity="0.85" />
                    <path d="M 146 250 Q 165 248 186 251" strokeWidth="3.5" opacity="0.7" />
                    {/* Dash 3 */}
                    <path d="M 200 251 Q 215 249 235 252" strokeWidth="4.8" opacity="0.9" />
                    <path d="M 202 249 Q 218 250 238 249" strokeWidth="3.2" opacity="0.75" />

                    {/* RIGHT DASHES */}
                    {/* Dash 4 */}
                    <path d="M 265 249 Q 285 251 302 248" strokeWidth="5" opacity="0.85" />
                    <path d="M 263 251 Q 282 249 300 252" strokeWidth="3" opacity="0.8" />
                    {/* Dash 5 */}
                    <path d="M 316 252 Q 335 249 356 250" strokeWidth="4.5" opacity="0.9" />
                    <path d="M 314 249 Q 336 251 354 248" strokeWidth="3.5" opacity="0.75" />
                    {/* Dash 6 */}
                    <path d="M 370 248 Q 390 251 412 249" strokeWidth="4.8" opacity="0.85" />
                    <path d="M 368 250 Q 388 248 410 251" strokeWidth="3.2" opacity="0.7" />

                    {/* PULSE SCAN ANIMATION (Expanding concentric rings emitting from the center) */}
                    <g>
                        <circle cx="250" cy="250" r="0" strokeWidth="5">
                            <animate attributeName="r" values="0; 80" dur="2.4s" repeatCount="indefinite" />
                            <animate attributeName="opacity" values="1; 0" dur="2.4s" repeatCount="indefinite" />
                            <animate attributeName="stroke-width" values="5; 1" dur="2.4s" repeatCount="indefinite" />
                        </circle>
                        <circle cx="250" cy="250" r="0" strokeWidth="5">
                            <animate attributeName="r" values="0; 80" dur="2.4s" begin="0.8s" repeatCount="indefinite" />
                            <animate attributeName="opacity" values="1; 0" dur="2.4s" begin="0.8s" repeatCount="indefinite" />
                            <animate attributeName="stroke-width" values="5; 1" dur="2.4s" begin="0.8s" repeatCount="indefinite" />
                        </circle>
                        <circle cx="250" cy="250" r="0" strokeWidth="5">
                            <animate attributeName="r" values="0; 80" dur="2.4s" begin="1.6s" repeatCount="indefinite" />
                            <animate attributeName="opacity" values="1; 0" dur="2.4s" begin="1.6s" repeatCount="indefinite" />
                            <animate attributeName="stroke-width" values="5; 1" dur="2.4s" begin="1.6s" repeatCount="indefinite" />
                        </circle>
                    </g>

                    {/* CENTER DOT (Drawn as a tight, overlapping scribbled spiral, pulsating) */}
                    <path className="center-dot" d="M 248 248 C 243 252, 256 258, 255 247 C 253 240, 244 244, 246 253 C 248 257, 256 253, 252 248 C 250 246, 248 249, 250 250" strokeWidth="8" opacity="0.95" />

                    {/* STRAY INK MARKS (Tiny dots around the drawing to simulate a quick pen sketch) */}
                    <path d="M 230 220 L 231 221" strokeWidth="3" opacity="0.6" />
                    <path d="M 280 270 L 281 269" strokeWidth="4" opacity="0.5" />
                    <path d="M 260 210 L 261 211" strokeWidth="2.5" opacity="0.4" />
                    <path d="M 190 280 L 191 281" strokeWidth="3.5" opacity="0.7" />
                    <path d="M 320 235 L 321 236" strokeWidth="3" opacity="0.5" />
                </g>
            </svg>
        </div>
    );
};
