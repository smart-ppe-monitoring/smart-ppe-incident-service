import { Request, Response, NextFunction } from "express";
import {
  AiVisionIntegrationService,
  aiVisionIntegrationService,
} from "./ai-vision.service";
import {
  AiVisionBatchInput,
  AiVisionEventInput,
} from "./ai-vision.validation";

export class AiVisionIntegrationController {
  constructor(
    private readonly service: AiVisionIntegrationService = aiVisionIntegrationService,
  ) {}

  ingestEvent = async (req: Request, res: Response, next: NextFunction) => {
    try {
      const result = await this.service.ingestEvent(req.body as AiVisionEventInput);
      res.status(201).json({
        success: true,
        data: result,
      });
    } catch (error) {
      next(error);
    }
  };

  ingestBatch = async (req: Request, res: Response, next: NextFunction) => {
    try {
      const body = req.body as AiVisionBatchInput;
      const result = await this.service.ingestBatch(body.events);
      res.status(result.failed === result.total ? 422 : 201).json({
        success: result.failed < result.total,
        data: result,
      });
    } catch (error) {
      next(error);
    }
  };
}

export const aiVisionIntegrationController =
  new AiVisionIntegrationController();
