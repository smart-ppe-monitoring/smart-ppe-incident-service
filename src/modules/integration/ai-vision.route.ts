import { Router } from "express";
import { requireInternalServiceToken } from "../../middlewares/internal-auth.middleware";
import { validate } from "../../middlewares/validate.middleware";
import { aiVisionIntegrationController } from "./ai-vision.controller";
import {
  aiVisionBatchInputSchema,
  aiVisionEventInputSchema,
} from "./ai-vision.validation";

export const aiVisionRouter = Router();

aiVisionRouter.post(
  "/events",
  requireInternalServiceToken,
  validate(aiVisionEventInputSchema),
  aiVisionIntegrationController.ingestEvent,
);

aiVisionRouter.post(
  "/events/batch",
  requireInternalServiceToken,
  validate(aiVisionBatchInputSchema),
  aiVisionIntegrationController.ingestBatch,
);
