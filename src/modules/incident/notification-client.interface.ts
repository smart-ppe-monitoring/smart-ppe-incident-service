export interface IncidentNotificationPayload {
  incidentId: string;
  siteId: string;
  cameraId: string;
  violationType: string;
  severity: string;
  description?: string;
  detectedAt: Date;
}

export interface NotificationService {
  dispatchIncidentNotification(payload: IncidentNotificationPayload): Promise<any>;
}

export const notificationService: NotificationService = {
  async dispatchIncidentNotification(payload: IncidentNotificationPayload) {
    // In standalone microservices mode, notification is dispatched asynchronously
    // via Kafka event bus or HTTP webhook to Notification Service (:8894)
    return { dispatched: true, incidentId: payload.incidentId };
  },
};
