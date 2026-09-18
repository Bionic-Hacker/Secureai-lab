import { useCallback, useRef, useState } from "react";
import { chatWithAssistant } from "../api.js";

function ChatMessage({ turn }) {
  if (turn.role === "system") {
    return <div className="chat-msg chat-msg--system mono">{turn.content}</div>;
  }
  return (
    <div className={`chat-msg chat-msg--${turn.role}`}>
      <div className="chat-msg__body">{turn.content}</div>
      {turn.guardrailFlags && turn.guardrailFlags.length > 0 && (
        <div className="chat-msg__flags">
          {turn.guardrailFlags.map((flag) => (
            <span key={flag} className="flag-pill">
              {flag.replace(/_/g, " ")}
            </span>
          ))}
        </div>
      )}
      {turn.meta && <div className="chat-msg__meta mono">{turn.meta}</div>}
    </div>
  );
}

export default function Assistant() {
  const [turns, setTurns] = useState([]);
  const [input, setInput] = useState("");
  const [sending, setSending] = useState(false);
  const [error, setError] = useState(null);
  const scrollRef = useRef(null);

  const scrollToBottom = useCallback(() => {
    requestAnimationFrame(() => {
      scrollRef.current?.scrollTo({ top: scrollRef.current.scrollHeight, behavior: "smooth" });
    });
  }, []);

  async function handleSend(e) {
    e.preventDefault();
    const message = input.trim();
    if (!message || sending) return;

    setError(null);
    setInput("");
    const userTurn = { role: "user", content: message };
    setTurns((prev) => [...prev, userTurn]);
    setSending(true);
    scrollToBottom();

    try {
      // Only user/assistant turns are valid history per ChatTurn's schema -
      // system (blocked-notice) turns are UI-only and never sent back.
      const history = turns
        .filter((t) => t.role === "user" || t.role === "assistant")
        .map((t) => ({ role: t.role, content: t.content }));

      const result = await chatWithAssistant({ message, history });

      if (result.blocked) {
        setTurns((prev) => [
          ...prev,
          {
            role: "system",
            content: `⚠ INPUT GUARDRAIL — request blocked · flags: ${result.guardrail_flags.join(", ")}`,
          },
        ]);
      } else {
        setTurns((prev) => [
          ...prev,
          {
            role: "assistant",
            content: result.response,
            guardrailFlags: result.guardrail_flags,
            meta: `${result.provider} · ${result.model} · ${result.latency_ms}ms`,
          },
        ]);
      }
    } catch (err) {
      setError(err.message);
      setTurns((prev) => [...prev, { role: "system", content: `⚠ ${err.message}` }]);
    } finally {
      setSending(false);
      scrollToBottom();
    }
  }

  return (
    <div>
      <header className="gov-header">
        <div>
          <h1 className="gov-header__title">AI Security Assistant</h1>
          <p className="gov-header__sub">
            Ask about vulnerabilities, review code, or get remediation guidance. Every input is screened before
            it reaches the model; every response is screened before it reaches you.
          </p>
        </div>
      </header>

      <div className="overview-panel" style={{ marginTop: "1.5rem" }}>
        <div className="chat-transcript" ref={scrollRef}>
          {turns.length === 0 ? (
            <p className="gov-empty">Ask a question to get started.</p>
          ) : (
            turns.map((turn, i) => <ChatMessage key={i} turn={turn} />)
          )}
          {sending && <div className="chat-msg chat-msg--system mono">Thinking…</div>}
        </div>

        <form className="chat-input-row" onSubmit={handleSend}>
          <input
            type="text"
            className="chat-input"
            placeholder="Ask about a vulnerability, paste code to review…"
            value={input}
            onChange={(e) => setInput(e.target.value)}
            disabled={sending}
          />
          <button type="submit" className="btn btn--accent" disabled={sending || !input.trim()}>
            Send
          </button>
        </form>
        {error && <p className="gov-error" style={{ marginTop: "0.75rem" }}>{error}</p>}
      </div>
    </div>
  );
}
