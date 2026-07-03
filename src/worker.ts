/**
 * Cloudflare Worker entry — fetch handler + scheduled cron.
 */

import app from "./app";
import { scheduledScan } from "./cron/scheduled";

export default {
  fetch: app.fetch,
  scheduled: scheduledScan,
};
