export interface QueueMessage {
  jobId: string;
  target: string;
  type: 'url' | 'repo';
  queuedAt: string;
  retryCount: number;
  scheduledInterval?: string;
}

export interface QueuePublishResult {
  success: boolean;
  messageId?: string;
  error?: string;
}
