// ABOUTME: Persistence boundary for compilation jobs
// ABOUTME: Includes an atomic in-memory implementation for tests and local execution

use crate::domain::{Job, JobStatus};
use anyhow::{anyhow, Result};
use async_trait::async_trait;
use std::{
    collections::HashMap,
    sync::{Arc, RwLock},
};

#[async_trait]
pub trait JobStore: Send + Sync {
    async fn create(&self, job: &Job) -> Result<()>;
    async fn get(&self, id: &str) -> Result<Option<Job>>;
    async fn save(&self, job: &Job) -> Result<()>;
    async fn recent_for_initiator(&self, initiated_by: &str, limit: usize) -> Result<Vec<Job>>;
    async fn claim_next(&self) -> Result<Option<Job>>;
}

#[derive(Clone, Default)]
pub struct MemoryJobStore {
    jobs: Arc<RwLock<HashMap<String, Job>>>,
}

#[async_trait]
impl JobStore for MemoryJobStore {
    async fn create(&self, job: &Job) -> Result<()> {
        let mut jobs = self
            .jobs
            .write()
            .map_err(|_| anyhow!("job store lock poisoned"))?;
        if jobs.contains_key(&job.id) {
            return Err(anyhow!("job {} already exists", job.id));
        }
        jobs.insert(job.id.clone(), job.clone());
        Ok(())
    }

    async fn get(&self, id: &str) -> Result<Option<Job>> {
        let jobs = self
            .jobs
            .read()
            .map_err(|_| anyhow!("job store lock poisoned"))?;
        Ok(jobs.get(id).cloned())
    }

    async fn save(&self, job: &Job) -> Result<()> {
        let mut jobs = self
            .jobs
            .write()
            .map_err(|_| anyhow!("job store lock poisoned"))?;
        if !jobs.contains_key(&job.id) {
            return Err(anyhow!("job {} does not exist", job.id));
        }
        jobs.insert(job.id.clone(), job.clone());
        Ok(())
    }

    async fn recent_for_initiator(&self, initiated_by: &str, limit: usize) -> Result<Vec<Job>> {
        let jobs = self
            .jobs
            .read()
            .map_err(|_| anyhow!("job store lock poisoned"))?;
        let mut matching: Vec<Job> = jobs
            .values()
            .filter(|job| job.initiated_by == initiated_by)
            .cloned()
            .collect();
        matching.sort_by(|left, right| {
            right
                .created_at
                .cmp(&left.created_at)
                .then_with(|| left.id.cmp(&right.id))
        });
        matching.truncate(limit);
        Ok(matching)
    }

    async fn claim_next(&self) -> Result<Option<Job>> {
        let mut jobs = self
            .jobs
            .write()
            .map_err(|_| anyhow!("job store lock poisoned"))?;
        let next_id = jobs
            .values()
            .filter(|job| job.status == JobStatus::Queued)
            .min_by(|left, right| {
                left.created_at
                    .cmp(&right.created_at)
                    .then_with(|| left.id.cmp(&right.id))
            })
            .map(|job| job.id.clone());

        let Some(next_id) = next_id else {
            return Ok(None);
        };
        let job = jobs
            .get_mut(&next_id)
            .ok_or_else(|| anyhow!("claimed job disappeared"))?;
        job.status = JobStatus::Running;
        Ok(Some(job.clone()))
    }
}
