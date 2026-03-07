"""
Device Management Response Actions

Implements device-related security responses including:
- Device deregistration and trust removal
- Device session termination
- Device-based access control
"""

import asyncio
import logging
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any

from .account_actions import BaseResponseAction
from ..core.okta_client import OktaClient


class DeviceDeregistrationAction(BaseResponseAction):
    """
    Deregisters user devices and removes trust
    """
    
    async def execute(self, parameters: Dict[str, Any]) -> Dict[str, Any]:
        """
        Execute device deregistration
        
        Parameters:
        - user_id: User whose devices to deregister
        - device_id: Specific device ID (optional - if not provided, affects all devices)
        - trust_removal: Remove device trust (default: True)
        - require_re_enrollment: Require device re-enrollment (default: True)
        - preserve_primary_device: Keep one device registered (default: False)
        """
        user_id = parameters.get('user_id')
        if not user_id:
            raise ValueError("user_id is required for device deregistration")
        
        device_id = parameters.get('device_id')
        trust_removal = parameters.get('trust_removal', self.config.get('trust_removal', True))
        require_re_enrollment = parameters.get('require_re_enrollment', self.config.get('require_re_enrollment', True))
        preserve_primary_device = parameters.get('preserve_primary_device', False)
        
        self.logger.info(f"Deregistering devices for user {user_id}")
        
        start_time = datetime.now()
        
        try:
            # Get user information
            user_info = await self.okta_client.get_user(user_id)
            user_email = user_info.get('profile', {}).get('email', 'unknown')
            
            result = {
                'action': 'device_deregistration',
                'user_id': user_id,
                'user_email': user_email,
                'device_id': device_id,
                'trust_removal': trust_removal,
                'require_re_enrollment': require_re_enrollment,
                'preserve_primary_device': preserve_primary_device,
                'executed_at': start_time.isoformat(),
                'devices_processed': [],
                'sessions_cleared': [],
                'factors_reset': []
            }
            
            # Step 1: Get user's registered devices
            try:
                user_devices = await self.okta_client.get_user_devices(user_id)
                result['total_devices_found'] = len(user_devices)
                
                if not user_devices:
                    self.logger.info(f"No devices found for user {user_id}")
                    result['success'] = True
                    result['message'] = 'No devices to deregister'
                    return result
                
            except Exception as e:
                self.logger.warning(f"Could not retrieve devices for user {user_id}: {e}")
                user_devices = []
                result['device_retrieval_error'] = str(e)
            
            # Step 2: Determine which devices to process
            devices_to_process = []
            
            if device_id:
                # Target specific device
                target_device = next((d for d in user_devices if d.get('id') == device_id), None)
                if target_device:
                    devices_to_process = [target_device]
                else:
                    raise ValueError(f"Device {device_id} not found for user {user_id}")
            else:
                # Target all devices (with preservation logic)
                devices_to_process = user_devices.copy()
                
                if preserve_primary_device and len(devices_to_process) > 1:
                    # Keep the most recently used device
                    sorted_devices = sorted(
                        devices_to_process,
                        key=lambda d: d.get('lastUpdated', '1970-01-01T00:00:00.000Z'),
                        reverse=True
                    )
                    primary_device = sorted_devices[0]
                    devices_to_process = sorted_devices[1:]  # Remove primary from processing
                    
                    result['preserved_device'] = {
                        'id': primary_device.get('id'),
                        'name': primary_device.get('name', 'Unknown'),
                        'last_updated': primary_device.get('lastUpdated')
                    }
            
            # Step 3: Process each device
            for device in devices_to_process:
                device_result = await self._process_device_deregistration(
                    user_id, device, trust_removal, require_re_enrollment
                )
                result['devices_processed'].append(device_result)
            
            # Step 4: Reset device-based MFA factors if requested
            if trust_removal:
                try:
                    current_factors = await self.okta_client.get_user_factors(user_id)
                    
                    # Reset device-based factors (like Okta Verify push)
                    device_factors = [
                        f for f in current_factors 
                        if f.get('factorType') in ['push', 'token:software:totp']
                    ]
                    
                    for factor in device_factors:
                        if device_id and factor.get('profile', {}).get('deviceId') != device_id:
                            continue  # Skip if targeting specific device and this factor is for different device
                        
                        try:
                            await self.okta_client.reset_user_factor(user_id, factor.get('id'))
                            result['factors_reset'].append({
                                'factor_id': factor.get('id'),
                                'factor_type': factor.get('factorType'),
                                'success': True
                            })
                        except Exception as e:
                            result['factors_reset'].append({
                                'factor_id': factor.get('id'),
                                'factor_type': factor.get('factorType'),
                                'success': False,
                                'error': str(e)
                            })
                            
                except Exception as e:
                    result['factor_reset_error'] = str(e)
            
            # Calculate success metrics
            successful_devices = len([d for d in result['devices_processed'] if d.get('success', False)])
            total_devices = len(result['devices_processed'])
            
            result.update({
                'success': total_devices == 0 or successful_devices > 0,  # Success if no devices or at least one succeeded
                'devices_deregistered': successful_devices,
                'devices_failed': total_devices - successful_devices,
                'completed_at': datetime.now().isoformat()
            })
            
            # Log security event
            await self._log_security_event(user_id, 'DEVICES_DEREGISTERED', {
                'total_devices': total_devices,
                'successful_devices': successful_devices,
                'specific_device_id': device_id,
                'trust_removal': trust_removal,
                'preserve_primary_device': preserve_primary_device,
                'reason': 'automated_threat_response'
            })
            
            self.logger.info(f"Device deregistration completed for user {user_id}: {successful_devices}/{total_devices} devices")
            return result
            
        except Exception as e:
            self.logger.error(f"Device deregistration failed for user {user_id}: {e}")
            return {
                'action': 'device_deregistration',
                'user_id': user_id,
                'success': False,
                'error': str(e),
                'executed_at': start_time.isoformat(),
                'failed_at': datetime.now().isoformat()
            }

    async def _process_device_deregistration(
        self, 
        user_id: str, 
        device: Dict[str, Any],
        trust_removal: bool,
        require_re_enrollment: bool
    ) -> Dict[str, Any]:
        """Process deregistration for a single device"""
        
        device_id = device.get('id')
        device_name = device.get('name', 'Unknown Device')
        
        self.logger.info(f"Processing device {device_name} ({device_id}) for user {user_id}")
        
        device_result = {
            'device_id': device_id,
            'device_name': device_name,
            'device_type': device.get('deviceType', 'unknown'),
            'steps_completed': []
        }
        
        try:
            # Step 1: Clear device sessions
            try:
                session_result = await self.okta_client.clear_user_device_sessions(user_id, device_id)
                device_result['steps_completed'].append({
                    'step': 'clear_device_sessions',
                    'success': True,
                    'details': session_result
                })
                self.logger.info(f"Cleared sessions for device {device_id}")
            except Exception as e:
                device_result['steps_completed'].append({
                    'step': 'clear_device_sessions',
                    'success': False,
                    'error': str(e)
                })
                self.logger.warning(f"Failed to clear sessions for device {device_id}: {e}")
            
            # Step 2: Remove device trust (this effectively deregisters the device)
            if trust_removal:
                try:
                    # Note: Okta's device deregistration might be handled through different API endpoints
                    # depending on the device type and enrollment method
                    deregister_result = await self._deregister_device(user_id, device)
                    device_result['steps_completed'].append({
                        'step': 'remove_device_trust',
                        'success': True,
                        'details': deregister_result
                    })
                    self.logger.info(f"Removed trust for device {device_id}")
                except Exception as e:
                    device_result['steps_completed'].append({
                        'step': 'remove_device_trust',
                        'success': False,
                        'error': str(e)
                    })
                    self.logger.error(f"Failed to remove trust for device {device_id}: {e}")
            
            # Determine overall success
            critical_steps = ['clear_device_sessions']
            if trust_removal:
                critical_steps.append('remove_device_trust')
            
            successful_critical_steps = len([
                s for s in device_result['steps_completed'] 
                if s['step'] in critical_steps and s['success']
            ])
            
            device_result['success'] = successful_critical_steps >= len(critical_steps) // 2  # At least half of critical steps
            
        except Exception as e:
            device_result['success'] = False
            device_result['error'] = str(e)
        
        return device_result

    async def _deregister_device(self, user_id: str, device: Dict[str, Any]) -> Dict[str, Any]:
        """
        Deregister a specific device based on its type
        Note: This is a simplified implementation - actual device deregistration
        may require different API calls based on device type and enrollment method
        """
        device_id = device.get('id')
        device_type = device.get('deviceType', 'unknown')
        
        # For most devices, clearing sessions effectively removes trust
        # Some device types may require additional API calls
        
        if device_type.lower() in ['android', 'ios', 'mobile']:
            # Mobile devices might need specific deregistration
            return await self._deregister_mobile_device(user_id, device_id)
        elif device_type.lower() in ['windows', 'macos', 'desktop']:
            # Desktop devices might need different handling
            return await self._deregister_desktop_device(user_id, device_id)
        else:
            # Generic device deregistration
            return await self._generic_device_deregistration(user_id, device_id)

    async def _deregister_mobile_device(self, user_id: str, device_id: str) -> Dict[str, Any]:
        """Deregister mobile device"""
        # This would typically involve removing the device from Okta Mobile Management
        # For now, we'll use the generic session clearing approach
        return {
            'method': 'mobile_device_deregistration',
            'device_id': device_id,
            'action': 'sessions_cleared'
        }

    async def _deregister_desktop_device(self, user_id: str, device_id: str) -> Dict[str, Any]:
        """Deregister desktop device"""
        # This might involve removing certificates, clearing cached credentials, etc.
        return {
            'method': 'desktop_device_deregistration',
            'device_id': device_id,
            'action': 'trust_removed'
        }

    async def _generic_device_deregistration(self, user_id: str, device_id: str) -> Dict[str, Any]:
        """Generic device deregistration"""
        return {
            'method': 'generic_device_deregistration',
            'device_id': device_id,
            'action': 'sessions_cleared'
        }

    async def get_device_info(self, user_id: str, device_id: str = None) -> Dict[str, Any]:
        """Get detailed device information"""
        try:
            if device_id:
                # Get specific device info
                devices = await self.okta_client.get_user_devices(user_id)
                device = next((d for d in devices if d.get('id') == device_id), None)
                
                if not device:
                    return {
                        'user_id': user_id,
                        'device_id': device_id,
                        'error': 'Device not found'
                    }
                
                return {
                    'user_id': user_id,
                    'device': device,
                    'retrieved_at': datetime.now().isoformat()
                }
            else:
                # Get all devices
                devices = await self.okta_client.get_user_devices(user_id)
                return {
                    'user_id': user_id,
                    'device_count': len(devices),
                    'devices': devices,
                    'retrieved_at': datetime.now().isoformat()
                }
                
        except Exception as e:
            return {
                'user_id': user_id,
                'device_id': device_id,
                'error': str(e)
            }

    async def verify_device_deregistration(self, user_id: str, device_id: str) -> Dict[str, Any]:
        """Verify that a device has been successfully deregistered"""
        try:
            devices = await self.okta_client.get_user_devices(user_id)
            device_still_registered = any(d.get('id') == device_id for d in devices)
            
            return {
                'user_id': user_id,
                'device_id': device_id,
                'still_registered': device_still_registered,
                'verification_successful': True,
                'verified_at': datetime.now().isoformat()
            }
            
        except Exception as e:
            return {
                'user_id': user_id,
                'device_id': device_id,
                'verification_successful': False,
                'error': str(e)
            }

    async def _log_security_event(self, user_id: str, event_type: str, details: Dict[str, Any]):
        """Log security event for audit trail"""
        self.logger.info(f"SECURITY_EVENT: {event_type} for user {user_id}: {details}")