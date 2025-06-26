import cv2
import datetime
import logging
from threading import Lock

logger = logging.getLogger(__name__)
camera_lock = Lock()

def detect_motion():
    try:
        with camera_lock:
            cam = cv2.VideoCapture(0)
            if not cam.isOpened():
                return {"error": "Camera not accessible"}
            ret, frame1 = cam.read()
            time.sleep(1)
            ret, frame2 = cam.read()
            if not (ret and frame1 is not None and frame2 is not None):
                return {"error": "Failed to capture frames"}
            diff = cv2.absdiff(frame1, frame2)
            gray = cv2.cvtColor(diff, cv2.COLOR_BGR2GRAY)
            blur = cv2.GaussianBlur(gray, (5, 5), 0)
            _, thresh = cv2.threshold(blur, 20, 255, cv2.THRESH_BINARY)
            contours, _ = cv2.findContours(thresh, cv2.RETR_TREE, cv2.CHAIN_APPROX_SIMPLE)
            motion_detected = any(cv2.contourArea(c) > 500 for c in contours)
            if motion_detected:
                timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
                path = f"static/motion_{timestamp}.jpg"
                cv2.imwrite(path, frame2)
                return {"status": "Motion detected", "file": path}
            return {"status": "No motion detected"}
    except Exception as e:
        logger.error(f"Motion detection error: {str(e)}")
        return {"error": f"Motion detection failed: {str(e)}"}
    finally:
        if 'cam' in locals():
            cam.release()