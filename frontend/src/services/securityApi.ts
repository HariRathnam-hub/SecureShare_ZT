import { api } from '../lib/api';
import type { SecurityOverview } from '../types/api';

export const securityApi = {
  overview: async (hours = 24) =>
    (await api.get<{ data: SecurityOverview }>('/security/overview', { params: { hours } })).data.data,
};
