/**
 * Maximum number of normalized observations retained from one analyzer run, whether it ran as a
 * single process or as merged shards. One constant keeps both paths on the same bound.
 */
export const ANALYZER_MAX_OBSERVATIONS = 50_000;
