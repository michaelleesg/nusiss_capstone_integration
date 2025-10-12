"""Guardrails integration for CTI pipeline security."""

import logging
from typing import Dict, Any, Optional
# from guardrails.hub import DetectJailbreak
# from guardrails import Guard

logger = logging.getLogger(__name__)


class CTIGuardrails:
    """Centralized guardrails for CTI pipeline."""

    def __init__(self):
        self.jailbreak_guard = None
        self._initialize_guards()

    def _initialize_guards(self):
        """Initialize guardrails validators."""
        try:
            # TEMPORARILY DISABLED: DetectJailbreak is too aggressive for CTI content
            # self.jailbreak_guard = Guard().use(DetectJailbreak())
            # logger.info("DetectJailbreak guardrail initialized successfully")

            self.jailbreak_guard = None
            logger.info("DetectJailbreak guardrail temporarily disabled due to false positives with CTI content")
        except Exception as e:
            logger.warning(f"Failed to initialize DetectJailbreak: {e}")
            self.jailbreak_guard = None

    def validate_user_input(self, text: str, agent_name: str = "unknown") -> Dict[str, Any]:
        """
        Validate user input for jailbreak attempts using guardrails-ai.

        Args:
            text: User input text to validate
            agent_name: Name of the agent processing the input

        Returns:
            Dict with validation results and sanitized text
        """
        validation_result = {
            "safe": True,
            "original_text": text,
            "sanitized_text": text,
            "blocked_reasons": []
        }

        if not text or not text.strip():
            return validation_result

        # Use guardrails-ai DetectJailbreak for validation
        if self.jailbreak_guard:
            try:
                # Validate with DetectJailbreak
                guard_result = self.jailbreak_guard.validate(text)

                # Extract the validated text from the guard result
                validated_text = text  # Default fallback

                if isinstance(guard_result, str):
                    validated_text = guard_result
                elif hasattr(guard_result, 'validated_output'):
                    validated_text = guard_result.validated_output
                elif hasattr(guard_result, 'raw_output'):
                    validated_text = guard_result.raw_output
                elif hasattr(guard_result, 'output'):
                    validated_text = guard_result.output
                else:
                    logger.debug(f"[{agent_name}] Unknown guard result type: {type(guard_result)}, using original text")

                # Ensure we have a string
                validated_text = str(validated_text) if validated_text is not None else text

                logger.debug(f"[{agent_name}] Guardrails validation passed")
                validation_result["sanitized_text"] = validated_text

            except Exception as e:
                # Jailbreak detected by guardrails-ai or validation error
                logger.warning(f"[{agent_name}] Guardrails blocked content: {str(e)}")
                validation_result["safe"] = False
                validation_result["blocked_reasons"].append(f"Blocked by guardrails-ai: {str(e)}")
                validation_result["sanitized_text"] = "[CONTENT BLOCKED - SECURITY VIOLATION]"
        else:
            # No guardrails available, pass through (with warning)
            logger.debug(f"[{agent_name}] No guardrails available, passing content through")
            validation_result["sanitized_text"] = text

        return validation_result

    def is_content_safe(self, text: str, agent_name: str = "unknown") -> bool:
        """Quick safety check - returns True if content is safe to process."""
        validation = self.validate_user_input(text, agent_name)
        return validation["safe"] and len(validation["blocked_reasons"]) == 0


# Global instance for reuse across agents
_cti_guardrails = None

def get_cti_guardrails() -> CTIGuardrails:
    """Get or create the global CTI guardrails instance."""
    global _cti_guardrails
    if _cti_guardrails is None:
        _cti_guardrails = CTIGuardrails()
    return _cti_guardrails