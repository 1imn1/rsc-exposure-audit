# rsc-exposure-audit
Black-box exposure audit for Next.js / React Server Components (RSC) endpoints (non-exploit).

#CVE-2025-55182 
#CVE-2025-55183
#CVE-2025-55184
#CVE-2025-67779 

Этот репозиторий содержит утилиты для безопасной (non-exploit) проверки публичной экспозиции React Server Components / Flight-протокола и связанной поверхности атак в приложениях Next.js.

Что делает:
	•	Выполняет black-box зондирование URL и определяет признаки Next.js (например, /_next/static/, x-nextjs-*).
	•	Определяет признаки RSC/Flight (например, Content-Type: text/x-component, “flight-like” структура ответа).
	•	Формирует консервативный риск-отчёт и рекомендации по обновлению/компенсирующим мерам (rate limiting, timeouts, body size limits).

Что НЕ делает:
	•	Не выполняет эксплуатационные проверки.
	•	Не отправляет PoC-пейлоады для RCE/DoS/утечки исходников.
	•	Не подтверждает уязвимость конкретных CVE “по сети” — только фиксирует экспозицию и условия риска. Для точного статуса требуется сверка версий react-server-dom-* и next внутри окружения.

