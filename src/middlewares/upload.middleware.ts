import multer from "multer";
import {
  MEDIA_LIMITS,
  SUPPORTED_IMAGE_MIME_TYPES,
} from "../common/constants/media.constant";
import { AppError } from "../common/errors/app-error";
import { ERROR_CODE } from "../common/errors/error-code";

/**
 * Middleware xử lý upload ảnh vào RAM memory buffer với các giới hạn an toàn:
 * - Kích thước tối đa theo cấu hình MEDIA_LIMITS.MAX_DIRECT_UPLOAD_BYTES (5MB) để bảo vệ heap và Event Loop
 * - Lọc MIME type chặt chẽ chỉ chấp nhận ảnh hợp lệ
 */
export const uploadImageMiddleware = multer({
  storage: multer.memoryStorage(),
  limits: {
    fileSize: MEDIA_LIMITS.MAX_DIRECT_UPLOAD_BYTES,
    files: 1,
  },
  fileFilter: (_req, file, cb) => {
    const isSupported = (
      SUPPORTED_IMAGE_MIME_TYPES as readonly string[]
    ).includes(file.mimetype.toLowerCase());
    if (isSupported) {
      cb(null, true);
    } else {
      cb(
        new AppError(
          "Định dạng tệp không được hỗ trợ. Chỉ chấp nhận các định dạng ảnh (JPEG, PNG, WebP, AVIF, GIF, TIFF)",
          400,
          ERROR_CODE.VALIDATION_ERROR,
        ),
      );
    }
  },
});
