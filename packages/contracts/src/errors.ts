export interface ValidationIssue {
  path: string;
  message: string;
}

export class SchemaValidationError extends Error {
  readonly issues: ValidationIssue[];

  constructor(message: string, issues: ValidationIssue[]) {
    super(message);
    this.name = "SchemaValidationError";
    this.issues = issues;
  }
}
