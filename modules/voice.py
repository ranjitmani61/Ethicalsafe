import speech_recognition as sr
import logging

logger = logging.getLogger(__name__)

def recognize_voice():
    try:
        recognizer = sr.Recognizer()
        with sr.Microphone() as source:
            logger.info("Listening...")
            recognizer.adjust_for_ambient_noise(source, duration=1)
            audio = recognizer.listen(source, timeout=5, phrase_time_limit=5)
            text = recognizer.recognize_google(audio)
            return {"recognized_text": text}
    except sr.WaitTimeoutError:
        return {"error": "No speech detected"}
    except sr.UnknownValueError:
        return {"error": "Could not understand audio"}
    except Exception as e:
        logger.error(f"Voice recognition error: {str(e)}")
        return {"error": f"Voice recognition failed: {str(e)}"}