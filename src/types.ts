export type Role = "client" | "admin";

export type ChatMessage = {
  role: "system" | "user" | "assistant";
  content: string;
};

export type Threat = {
  type: string;
  ruleId: string;
  message: string;
  sample?: string;
};

export type AuthenticatedKey = {
  keyId: string;
  role: Role;
  rateLimitPerMinute: number;
};

export type RedactionToken = {
  token: string;
  category: "email" | "phone" | "israeli_id";
  value: string;
};
