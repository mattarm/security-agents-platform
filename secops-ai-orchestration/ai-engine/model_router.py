"""
Model Router - Intelligent Claude model selection for cost optimization
Routes alerts to Haiku (70%), Sonnet (25%), or Opus (5%) based on complexity
"""

import asyncio
import logging
from datetime import datetime, timezone
from typing import Dict, Any, List
import boto3
from botocore.exceptions import ClientError
import json

logger = logging.getLogger(__name__)

class ModelRouter:
    """
    Intelligent routing to Claude models based on alert complexity and cost optimization
    
    Strategy:
    - Haiku (70%): Simple classification, routing, status updates
    - Sonnet (25%): Investigation analysis, ticket generation, correlation
    - Opus (5%): Complex threat analysis, compliance reasoning, novel threats
    """
    
    def __init__(self, config: Dict[str, Any]):
        """Initialize model router with Bedrock configuration"""
        self.config = config
        self.bedrock_client = None
        self.model_mapping = {
            'haiku': 'anthropic.claude-3-haiku-20240307-v1:0',
            'sonnet': 'anthropic.claude-3-sonnet-20240229-v1:0', 
            'opus': 'anthropic.claude-3-opus-20240229-v1:0'
        }
        
        # Model selection thresholds and criteria
        self.complexity_thresholds = {
            'simple': 0.3,     # Route to Haiku
            'moderate': 0.7,   # Route to Sonnet  
            'complex': 1.0     # Route to Opus
        }
        
        # Cost and performance tracking
        self.usage_stats = {
            'haiku': {'calls': 0, 'total_tokens': 0, 'avg_latency': 0},
            'sonnet': {'calls': 0, 'total_tokens': 0, 'avg_latency': 0},
            'opus': {'calls': 0, 'total_tokens': 0, 'avg_latency': 0}
        }
        
        # Circuit breaker for model failures
        self.circuit_breakers = {
            'haiku': {'failures': 0, 'last_failure': None, 'is_open': False},
            'sonnet': {'failures': 0, 'last_failure': None, 'is_open': False},
            'opus': {'failures': 0, 'last_failure': None, 'is_open': False}
        }
        
    async def initialize(self):
        """Initialize AWS Bedrock client with VPC configuration"""
        try:
            session = boto3.Session(
                region_name=self.config.get('region', 'us-east-1'),
                aws_access_key_id=self.config.get('access_key_id'),
                aws_secret_access_key=self.config.get('secret_access_key')
            )
            
            self.bedrock_client = session.client(
                'bedrock-runtime',
                endpoint_url=self.config.get('vpc_endpoint_url'),  # VPC endpoint
                config=boto3.session.Config(
                    retries={'max_attempts': 3, 'mode': 'adaptive'}
                )
            )
            
            logger.info("Bedrock client initialized with VPC configuration")
            
        except Exception as e:
            logger.error(f"Failed to initialize Bedrock client: {str(e)}")
            raise
    
    async def select_model(self, alert) -> str:
        """
        Select appropriate Claude model based on alert complexity
        
        Decision factors:
        1. Alert severity and source
        2. Evidence complexity and volume
        3. Required analysis depth
        4. Cost optimization targets
        5. Model availability (circuit breaker)
        """
        
        complexity_score = await self._calculate_complexity_score(alert)
        
        # Apply circuit breaker logic
        available_models = self._get_available_models()
        
        # Select model based on complexity and availability
        if complexity_score <= self.complexity_thresholds['simple'] and 'haiku' in available_models:
            selected_model = 'haiku'
        elif complexity_score <= self.complexity_thresholds['moderate'] and 'sonnet' in available_models:
            selected_model = 'sonnet'
        elif 'opus' in available_models:
            selected_model = 'opus'
        else:
            # Fallback to best available model
            selected_model = available_models[0] if available_models else 'haiku'
        
        # Validate against usage quotas to maintain cost targets
        if not self._check_usage_quota(selected_model):
            selected_model = await self._apply_cost_optimization(selected_model, available_models)
        
        logger.info(f"Selected model {selected_model} for alert {alert.id} (complexity: {complexity_score:.2f})")
        return selected_model
    
    async def _calculate_complexity_score(self, alert) -> float:
        """
        Calculate complexity score for model routing (0.0 - 1.0)
        
        Factors:
        - Severity: Critical/High = +0.3, Medium = +0.2, Low = +0.1
        - Evidence volume: >10 items = +0.2, 5-10 = +0.1, <5 = +0.0
        - Source criticality: Core systems = +0.2, Network = +0.1, Edge = +0.0
        - Pattern novelty: Unknown patterns = +0.3, Known patterns = +0.0
        - Context richness: Multi-source = +0.2, Single source = +0.0
        """
        
        score = 0.0
        
        # Severity scoring
        severity_scores = {
            'critical': 0.3,
            'high': 0.3, 
            'medium': 0.2,
            'low': 0.1
        }
        score += severity_scores.get(alert.severity.value, 0.1)
        
        # Evidence complexity
        evidence_count = len(alert.evidence) if alert.evidence else 0
        if evidence_count > 10:
            score += 0.2
        elif evidence_count >= 5:
            score += 0.1
        
        # Source criticality
        high_criticality_sources = ['windows_dc', 'database', 'firewall', 'proxy']
        if any(source in alert.source.lower() for source in high_criticality_sources):
            score += 0.2
        elif 'network' in alert.source.lower():
            score += 0.1
        
        # Pattern analysis (simplified - would integrate with threat intel)
        if self._is_novel_pattern(alert):
            score += 0.3
        
        # Multi-source correlation
        if alert.metadata and len(alert.metadata.get('sources', [])) > 1:
            score += 0.2
        
        return min(score, 1.0)  # Cap at 1.0
    
    def _is_novel_pattern(self, alert) -> bool:
        """Check if alert represents a novel or unknown threat pattern"""
        # Simplified implementation - would integrate with threat intelligence
        novel_indicators = ['unknown', 'novel', 'zero-day', 'suspicious', 'anomalous']
        alert_text = f"{alert.title} {alert.description}".lower()
        return any(indicator in alert_text for indicator in novel_indicators)
    
    def _get_available_models(self) -> List[str]:
        """Get list of available models based on circuit breaker status"""
        available = []
        for model in ['haiku', 'sonnet', 'opus']:
            breaker = self.circuit_breakers[model]
            if not breaker['is_open']:
                available.append(model)
        
        # If all models are down, reset circuit breakers (last resort)
        if not available:
            logger.warning("All models unavailable, resetting circuit breakers")
            for model in self.circuit_breakers:
                self.circuit_breakers[model]['is_open'] = False
            available = ['haiku', 'sonnet', 'opus']
        
        return available
    
    def _check_usage_quota(self, model: str) -> bool:
        """Check if model usage is within cost optimization targets"""
        stats = self.usage_stats[model]
        
        # Daily usage limits for cost control
        daily_limits = {
            'haiku': 2000,    # ~$50-100/month target
            'sonnet': 800,    # ~$30-80/month target
            'opus': 200       # ~$20-70/month target
        }
        
        # Simple daily quota check (would be more sophisticated in production)
        daily_calls = stats['calls']  # Simplified - would track per day
        return daily_calls < daily_limits[model]
    
    async def _apply_cost_optimization(self, preferred_model: str, available_models: List[str]) -> str:
        """Apply cost optimization when preferred model exceeds quota"""
        
        # Cost hierarchy: prefer cheaper models when over quota
        cost_hierarchy = ['haiku', 'sonnet', 'opus']
        
        for model in cost_hierarchy:
            if model in available_models and self._check_usage_quota(model):
                logger.info(f"Cost optimization: downgraded from {preferred_model} to {model}")
                return model
        
        # If all models are over quota, use cheapest available
        cheapest_available = next((m for m in cost_hierarchy if m in available_models), 'haiku')
        logger.warning(f"All models over quota, using {cheapest_available}")
        return cheapest_available
    
    async def invoke_model(self, model: str, prompt: str, alert_context: Dict[str, Any]) -> Dict[str, Any]:
        """
        Invoke Claude model via AWS Bedrock with error handling
        """
        start_time = datetime.now(timezone.utc)
        
        try:
            if not self.bedrock_client:
                await self.initialize()
            
            # Prepare request body
            request_body = {
                "anthropic_version": "bedrock-2023-05-31",
                "max_tokens": self._get_max_tokens(model),
                "temperature": 0.1,  # Low temperature for consistent analysis
                "top_p": 0.9,
                "messages": [
                    {
                        "role": "user",
                        "content": prompt
                    }
                ]
            }
            
            # Invoke model
            response = self.bedrock_client.invoke_model(
                modelId=self.model_mapping[model],
                body=json.dumps(request_body)
            )
            
            # Parse response
            response_body = json.loads(response['body'].read())
            content = response_body['content'][0]['text']
            
            # Calculate latency
            latency_ms = (datetime.now(timezone.utc) - start_time).total_seconds() * 1000
            
            # Update usage statistics
            self._update_usage_stats(model, response_body, latency_ms)
            
            # Reset circuit breaker on successful call
            self.circuit_breakers[model]['failures'] = 0
            
            # Parse structured response from Claude
            analysis = self._parse_claude_response(content)
            
            return analysis
            
        except ClientError as e:
            error_code = e.response['Error']['Code']
            logger.error(f"Bedrock error for model {model}: {error_code}")
            
            # Update circuit breaker
            await self._handle_model_failure(model, str(e))
            raise
            
        except Exception as e:
            logger.error(f"Unexpected error invoking model {model}: {str(e)}")
            await self._handle_model_failure(model, str(e))
            raise
    
    def _get_max_tokens(self, model: str) -> int:
        """Get appropriate max tokens for each model"""
        token_limits = {
            'haiku': 2048,    # Concise responses for simple tasks
            'sonnet': 4096,   # Detailed analysis
            'opus': 8192      # Comprehensive investigation
        }
        return token_limits.get(model, 2048)
    
    def _parse_claude_response(self, content: str) -> Dict[str, Any]:
        """Parse Claude's structured response into analysis components"""
        
        # Initialize default response structure
        analysis = {
            'category': 'investigation_required',
            'confidence': 0.5,
            'reasoning_chain': [],
            'risk_assessment': 'medium',
            'recommended_action': 'Manual review required',
            'raw_response': content
        }
        
        # Parse structured fields from Claude's response
        lines = content.split('\n')
        current_section = None
        reasoning_lines = []
        
        for line in lines:
            line = line.strip()
            
            if line.startswith('Category:'):
                category = line.split(':', 1)[1].strip().lower()
                analysis['category'] = category
                
            elif line.startswith('Confidence:'):
                try:
                    confidence_str = line.split(':', 1)[1].strip()
                    confidence_value = float(confidence_str.replace('%', '')) / 100
                    analysis['confidence'] = confidence_value
                except (ValueError, IndexError):
                    pass
                    
            elif line.startswith('Risk Assessment:'):
                risk = line.split(':', 1)[1].strip().lower()
                analysis['risk_assessment'] = risk
                
            elif line.startswith('Recommended Action:'):
                action = line.split(':', 1)[1].strip()
                analysis['recommended_action'] = action
                
            elif line.startswith('Reasoning:'):
                current_section = 'reasoning'
                
            elif current_section == 'reasoning' and line:
                reasoning_lines.append(line)
        
        if reasoning_lines:
            analysis['reasoning_chain'] = reasoning_lines
        
        return analysis
    
    def _update_usage_stats(self, model: str, response_body: Dict[str, Any], latency_ms: float):
        """Update model usage statistics for cost tracking"""
        stats = self.usage_stats[model]
        
        # Update call count
        stats['calls'] += 1
        
        # Update token usage (if available in response)
        if 'usage' in response_body:
            stats['total_tokens'] += response_body['usage'].get('output_tokens', 0)
        
        # Update average latency
        current_avg = stats['avg_latency']
        call_count = stats['calls']
        new_avg = ((current_avg * (call_count - 1)) + latency_ms) / call_count
        stats['avg_latency'] = new_avg
    
    async def _handle_model_failure(self, model: str, error: str):
        """Handle model failures and update circuit breaker"""
        breaker = self.circuit_breakers[model]
        breaker['failures'] += 1
        breaker['last_failure'] = datetime.now(timezone.utc)
        
        # Open circuit breaker after 3 consecutive failures
        if breaker['failures'] >= 3:
            breaker['is_open'] = True
            logger.warning(f"Circuit breaker opened for model {model} after {breaker['failures']} failures")
            
            # Schedule circuit breaker reset (simplified - would use proper scheduler)
            asyncio.create_task(self._reset_circuit_breaker(model, delay_seconds=300))  # 5 minute cooldown
    
    async def _reset_circuit_breaker(self, model: str, delay_seconds: int):
        """Reset circuit breaker after cooldown period"""
        await asyncio.sleep(delay_seconds)
        
        breaker = self.circuit_breakers[model]
        breaker['is_open'] = False
        breaker['failures'] = 0
        logger.info(f"Circuit breaker reset for model {model}")
    
    async def health_check(self) -> Dict[str, Any]:
        """Health check for model router"""
        return {
            'status': 'healthy' if self.bedrock_client else 'initializing',
            'available_models': self._get_available_models(),
            'usage_stats': self.usage_stats,
            'circuit_breakers': {
                model: {
                    'status': 'open' if breaker['is_open'] else 'closed',
                    'failures': breaker['failures']
                }
                for model, breaker in self.circuit_breakers.items()
            }
        }
    
    def get_cost_metrics(self) -> Dict[str, Any]:
        """Get current cost and usage metrics"""
        total_calls = sum(stats['calls'] for stats in self.usage_stats.values())
        
        # Estimated costs based on usage (would integrate with actual billing)
        estimated_costs = {
            'haiku': self.usage_stats['haiku']['calls'] * 0.001,
            'sonnet': self.usage_stats['sonnet']['calls'] * 0.005,
            'opus': self.usage_stats['opus']['calls'] * 0.020
        }
        
        total_cost = sum(estimated_costs.values())
        
        return {
            'total_calls': total_calls,
            'model_distribution': {
                model: (stats['calls'] / total_calls * 100) if total_calls > 0 else 0
                for model, stats in self.usage_stats.items()
            },
            'estimated_daily_cost_usd': total_cost,
            'estimated_monthly_cost_usd': total_cost * 30,
            'cost_by_model': estimated_costs,
            'performance_metrics': {
                model: {
                    'avg_latency_ms': stats['avg_latency'],
                    'total_tokens': stats['total_tokens']
                }
                for model, stats in self.usage_stats.items()
            }
        }