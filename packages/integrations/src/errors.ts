export class IntegrationHttpError extends Error {
  readonly status: number;
  readonly url: string;

  constructor(message: string, status: number, url: string) {
    super(message);
    this.name = "IntegrationHttpError";
    this.status = status;
    this.url = url;
  }
}
