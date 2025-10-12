"""Base AI agent class with detailed logging and token tracking."""

import json
import logging
import os
import time
from abc import ABC, abstractmethod
from typing import Any, Dict, Optional
from ...state import GraphState
from openai import OpenAI

from dotenv import load_dotenv
load_dotenv()

LLM_API_KEY = os.getenv("OPENAI_API_KEY")
LLM_MODEL = os.getenv("OPENAI_MODEL", "gpt-4o")

logger = logging.getLogger(__name__)


class BaseAgent(ABC):

    def __init__(self, name: str):
        self.token_usage = {
            "prompt_tokens": 0,
            "completion_tokens": 0,
            "total_tokens": 0,
        }
        self.processing_time = 0.0
        self.last_prompt = ""
        self.last_input = ""
        self.last_output = ""
        self.name = name
        self.logger = logging.getLogger(f"agent.{name}")

        # Log LLM configuration on initialization
        self.init_default_llm_config()

    def init_default_llm_config(self):
        """Log LLM configuration settings."""
        config = {
            "model": LLM_MODEL,
            "temperature": 0.1,
            "max_tokens": 2000,
            "api_key_configured": bool(LLM_API_KEY)
        }
        self.logger.info(f"[{self.name}] Agent initialized - LLM Configuration: {config}")

    def call_llm(self, system_prompt: str, user_input: str) -> str:
        """Call LLM with system and user prompts, tracking tokens."""
        if not LLM_API_KEY:
            self.logger.warning(f"[{self.name.upper()}] No LLM API KEY found, returning empty JSON")
            return "{}"

        # Validate user input for jailbreak attempts and security issues
        from .guardrails_helper import get_cti_guardrails
        guardrails = get_cti_guardrails()

        validation_result = guardrails.validate_user_input(user_input, self.name)

        if not validation_result["safe"]:
            self.logger.error(f"[{self.name.upper()}] Input blocked by guardrails: {validation_result['blocked_reasons']}")
            return "{}"

        # Use sanitized text for LLM call
        sanitized_input = validation_result["sanitized_text"]

        # Ensure sanitized_input is a string (safety check)
        if not isinstance(sanitized_input, str):
            self.logger.warning(f"[{self.name.upper()}] Sanitized input is not a string: {type(sanitized_input)}, converting...")
            sanitized_input = str(sanitized_input)

        try:
            self.last_prompt = system_prompt
            self.last_input = sanitized_input

            client = OpenAI(timeout=30.0, max_retries=1)

            start_time = time.time()
            response = client.chat.completions.create(
                model=LLM_MODEL,
                messages=[
                    {"role": "system", "content": system_prompt},
                    {"role": "user", "content": sanitized_input}
                ],
                temperature=0.1,
                max_tokens=2000
            )
            self.processing_time = time.time() - start_time

            # Extract token usage
            if response.usage:
                self.token_usage.update({
                    "prompt_tokens": response.usage.prompt_tokens,
                    "completion_tokens": response.usage.completion_tokens,
                    "total_tokens": response.usage.total_tokens
                })

            content = response.choices[0].message.content
            self.last_output = content

            # Log response with agent name
            self.logger.info(f"[{self.name.upper()}] LLM Response - Tokens: {self.token_usage}, "
                           f"Time: {self.processing_time:.2f}s")

            return content

        except Exception as e:
            self.processing_time = time.time() - start_time if 'start_time' in locals() else 0
            if "timeout" in str(e).lower() or "timed out" in str(e).lower():
                self.logger.error(f"[{self.name.upper()}] LLM call TIMED OUT after {self.processing_time:.2f}s: {e}")
            else:
                self.logger.error(f"[{self.name.upper()}] LLM call failed after {self.processing_time:.2f}s: {e}")
            self.last_output = "{}"
            return "{}"

    def update_state_token_usage(self, state):
        """Update the state's token usage with this agent's usage."""
        from ...state import GraphState

        if isinstance(state, GraphState) and hasattr(self, 'token_usage') and hasattr(self, 'processing_time'):
            # Update overall totals
            state.token_usage["input_tokens"] += self.token_usage.get("prompt_tokens", 0)
            state.token_usage["output_tokens"] += self.token_usage.get("completion_tokens", 0)
            state.token_usage["total_tokens"] += self.token_usage.get("total_tokens", 0)
            state.token_usage["processing_time"] += self.processing_time

            # Update agent-specific data
            if self.name not in state.token_usage["agents"]:
                state.token_usage["agents"][self.name] = {
                    "input_tokens": 0,
                    "output_tokens": 0,
                    "total_tokens": 0,
                    "processing_time": 0.0,
                    "calls": 0
                }

            agent_data = state.token_usage["agents"][self.name]
            agent_data["input_tokens"] += self.token_usage.get("prompt_tokens", 0)
            agent_data["output_tokens"] += self.token_usage.get("completion_tokens", 0)
            agent_data["total_tokens"] += self.token_usage.get("total_tokens", 0)
            agent_data["processing_time"] += self.processing_time
            agent_data["calls"] += 1

    def estimate_tokens(self, text: str) -> int:
        """Estimate token count for text (rough approximation)."""
        return len(text) // 4

    @abstractmethod
    def get_system_prompt(self) -> str:
        """Get the system prompt for this agent."""
        pass

    def log_agent_start(self, additional_info: str = ""):
        """Log when agent starts processing."""
        info_str = f" - {additional_info}" if additional_info else ""
        self.logger.info(f"[{self.name.upper()}] Starting processing{info_str}")

    @abstractmethod
    def process(self, state: GraphState) -> GraphState:
        """Process the state and return updated state."""
        pass

    def process_with_token_tracking(self, state: GraphState) -> GraphState:
        """Wrapper for process that ensures token usage is tracked."""
        # Reset token usage for this processing call
        self.token_usage = {"prompt_tokens": 0, "completion_tokens": 0, "total_tokens": 0}
        self.processing_time = 0.0

        # Call the actual process method
        result_state = self.process(state)

        # Update state token usage
        self.update_state_token_usage(result_state)

        return result_state

    def log_processing(self, action: str, details: Optional[Dict[str, Any]] = None):
        """Log processing information with enhanced details including token usage."""
        log_data = {
            "processing_time": f"{self.processing_time:.2f}s",
            "token_usage": self.token_usage.copy()
        }
        if details:
            log_data.update(details)
        self.logger.info(f"[{self.name.upper()}] {action} - {log_data}")

    def get_debug_info(self) -> Dict[str, Any]:
        """Get detailed debug information about the agent's last run."""
        return {
            "agent_name": self.name,
            "system_prompt": self.last_prompt,
            "input_data": self.last_input,
            "output_data": self.last_output,
            "token_usage": self.token_usage.copy(),
            "processing_time_seconds": self.processing_time,
            "estimated_input_tokens": self.estimate_tokens(self.last_input),
            "estimated_prompt_tokens": self.estimate_tokens(self.last_prompt)
        }

    def process_with_debug(self, state: GraphState) -> tuple[GraphState, Dict[str, Any]]:
        """Process with full debug information capture (used in testing)."""
        start_time = time.time()
        result_state = self.process(state)
        total_time = time.time() - start_time

        debug_info = {
            **self.get_debug_info(),
            "total_processing_time": total_time
        }
        return result_state, debug_info