import { Consumer, Kafka, logLevel } from "kafkajs";
import { envConfig } from "../../config/env.config";
import { AppError } from "../../common/errors/app-error";
import {
  KAFKA_CONSUMER_GROUPS,
  KAFKA_TOPICS,
} from "../../common/constants/kafka.constant";
import {
  AiVisionIntegrationService,
  aiVisionIntegrationService,
} from "./ai-vision.service";
import { aiVisionEventInputSchema } from "./ai-vision.validation";

export interface KafkaIngestResult {
  success: boolean;
  topic: string;
  incidentId?: string;
  error?: string;
  retryable?: boolean;
}

const KAFKA_RECONNECT_DELAY_MS = 15_000;

export class AiVisionKafkaConsumer {
  private consumer: Consumer | null = null;
  private isRunning = false;
  private isStopped = false;
  private reconnectTimer: ReturnType<typeof setTimeout> | null = null;

  constructor(
    private readonly integrationService: Pick<
      AiVisionIntegrationService,
      "ingestEvent"
    > = aiVisionIntegrationService,
  ) {}

  get status() {
    return {
      isRunning: this.isRunning,
      group: KAFKA_CONSUMER_GROUPS.INCIDENT_SERVICE,
      topic: envConfig.kafka.violationTopic || KAFKA_TOPICS.PPE_VIOLATION_DETECTED,
    };
  }

  async processRawMessage(rawInput: unknown): Promise<KafkaIngestResult> {
    const topic =
      envConfig.kafka.violationTopic || KAFKA_TOPICS.PPE_VIOLATION_DETECTED;

    let parsedJson: unknown = rawInput;
    if (typeof rawInput === "string") {
      try {
        parsedJson = JSON.parse(rawInput);
      } catch (err: any) {
        return {
          success: false,
          topic,
          error: `Invalid JSON payload: ${err?.message || "parse error"}`,
          retryable: false,
        };
      }
    }

    const validated = aiVisionEventInputSchema.safeParse(parsedJson);
    if (!validated.success) {
      const msg = validated.error.issues
        .map((i) => `${i.path.join(".")}: ${i.message}`)
        .join("; ");
      return {
        success: false,
        topic,
        error: `Validation failed: ${msg}`,
        retryable: false,
      };
    }

    try {
      const res = await this.integrationService.ingestEvent(validated.data);
      return {
        success: true,
        topic,
        incidentId: res.incident.id,
      };
    } catch (err: any) {
      const isClientError =
        err instanceof AppError &&
        err.statusCode >= 400 &&
        err.statusCode < 500;
      return {
        success: false,
        topic,
        error: err?.message || "Incident ingestion failed",
        retryable: !isClientError,
      };
    }
  }

  async handleMessageValue(rawValue: string): Promise<KafkaIngestResult> {
    const topic =
      envConfig.kafka.violationTopic || KAFKA_TOPICS.PPE_VIOLATION_DETECTED;
    const result = await this.processRawMessage(rawValue);
    if (!result.success) {
      if (result.retryable) {
        throw new Error(
          `[Incident Kafka Consumer] Transient error processing message on ${topic}: ${result.error}`,
        );
      }
      console.warn(
        `[Incident Kafka Consumer] Dropped non-retryable message on ${topic}: ${result.error}`,
      );
    }
    return result;
  }

  private scheduleReconnect(): void {
    if (this.isStopped || this.reconnectTimer) {
      return;
    }
    this.reconnectTimer = setTimeout(() => {
      this.reconnectTimer = null;
      if (!this.isStopped && !this.isRunning) {
        void this.start();
      }
    }, KAFKA_RECONNECT_DELAY_MS);
    this.reconnectTimer.unref?.();
  }

  async start(): Promise<void> {
    if (!envConfig.kafka.enabled || envConfig.kafka.brokers.length === 0) {
      return;
    }
    this.isStopped = false;
    if (this.isRunning) {
      return;
    }

    const topic =
      envConfig.kafka.violationTopic || KAFKA_TOPICS.PPE_VIOLATION_DETECTED;

    try {
      const kafka = new Kafka({
        clientId: "smart-ppe-incident-service",
        brokers: envConfig.kafka.brokers,
        logLevel: logLevel.WARN,
        retry: { retries: 3 },
      });
      this.consumer = kafka.consumer({
        groupId: KAFKA_CONSUMER_GROUPS.INCIDENT_SERVICE,
      });
      await this.consumer.connect();
      await this.consumer.subscribe({ topic, fromBeginning: false });
      await this.consumer.run({
        eachMessage: async ({ message }) => {
          if (!message.value) return;
          await this.handleMessageValue(message.value.toString("utf-8"));
        },
      });
      this.isRunning = true;
      console.log(
        `[Incident Service] ✅ Kafka consumer subscribed to '${topic}' (${envConfig.kafka.brokers.join(",")})`,
      );
    } catch (err: any) {
      console.warn(
        `[Incident Service] ⚠️ Kafka consumer unavailable (${err?.message || err}). Scheduling reconnect.`,
      );
      this.isRunning = false;
      this.consumer = null;
      this.scheduleReconnect();
    }
  }

  async stop(): Promise<void> {
    this.isStopped = true;
    if (this.reconnectTimer) {
      clearTimeout(this.reconnectTimer);
      this.reconnectTimer = null;
    }
    if (!this.consumer) {
      this.isRunning = false;
      return;
    }
    try {
      await this.consumer.disconnect();
    } catch {
      // Ignore disconnect errors during shutdown
    } finally {
      this.consumer = null;
      this.isRunning = false;
    }
  }
}

export const defaultAiVisionConsumer = new AiVisionKafkaConsumer();
