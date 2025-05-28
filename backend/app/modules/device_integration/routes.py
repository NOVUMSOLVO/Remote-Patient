"""
Device Integration Module
Seamless integration with wearable devices via Bluetooth/API
"""

from flask import Blueprint, request, jsonify, current_app
from flask_jwt_extended import jwt_required, get_jwt_identity
from datetime import datetime, timedelta
import json

from app import db
from app.models import Device, DeviceType, HealthRecord, PatientProfile, User
from app.utils.bluetooth_handler import BluetoothDeviceHandler
from app.utils.device_apis import DeviceAPIHandler
from app.utils.data_validation import validate_health_data

device_bp = Blueprint('device', __name__)

@device_bp.route('/register', methods=['POST'])
@jwt_required()
def register_device():
    """Register a new medical device"""
    try:
        user_id = get_jwt_identity()
        user = User.query.get(user_id)
        
        if not user or not user.patient_profile:
            return jsonify({'error': 'Patient profile not found'}), 404
        
        data = request.get_json()
        
        # Validate required fields
        required_fields = ['device_name', 'device_type', 'device_id']
        for field in required_fields:
            if not data.get(field):
                return jsonify({'error': f'{field} is required'}), 400
        
        # Validate device type
        try:
            device_type = DeviceType(data['device_type'])
        except ValueError:
            return jsonify({'error': 'Invalid device type'}), 400
        
        # Check if device already exists
        existing_device = Device.query.filter_by(device_id=data['device_id']).first()
        if existing_device:
            return jsonify({'error': 'Device already registered'}), 409
        
        # Create new device
        device = Device(
            patient_id=user.patient_profile.id,
            device_name=data['device_name'].strip(),
            device_type=device_type,
            device_id=data['device_id'].strip(),
            manufacturer=data.get('manufacturer', '').strip() or None,
            model=data.get('model', '').strip() or None,
            firmware_version=data.get('firmware_version', '').strip() or None
        )
        
        db.session.add(device)
        db.session.commit()
        
        return jsonify({
            'message': 'Device registered successfully',
            'device': {
                'id': device.id,
                'device_name': device.device_name,
                'device_type': device.device_type.value,
                'device_id': device.device_id,
                'manufacturer': device.manufacturer,
                'model': device.model,
                'is_active': device.is_active,
                'created_at': device.created_at.isoformat()
            }
        }), 201
        
    except Exception as e:
        db.session.rollback()
        current_app.logger.error(f'Device registration error: {str(e)}')
        return jsonify({'error': 'Device registration failed'}), 500

@device_bp.route('/', methods=['GET'])
@jwt_required()
def get_devices():
    """Get all devices for the current patient"""
    try:
        user_id = get_jwt_identity()
        user = User.query.get(user_id)
        
        if not user or not user.patient_profile:
            return jsonify({'error': 'Patient profile not found'}), 404
        
        devices = Device.query.filter_by(patient_id=user.patient_profile.id).all()
        
        device_list = []
        for device in devices:
            device_list.append({
                'id': device.id,
                'device_name': device.device_name,
                'device_type': device.device_type.value,
                'device_id': device.device_id,
                'manufacturer': device.manufacturer,
                'model': device.model,
                'firmware_version': device.firmware_version,
                'is_active': device.is_active,
                'last_sync': device.last_sync.isoformat() if device.last_sync else None,
                'created_at': device.created_at.isoformat()
            })
        
        return jsonify({'devices': device_list}), 200
        
    except Exception as e:
        current_app.logger.error(f'Get devices error: {str(e)}')
        return jsonify({'error': 'Failed to retrieve devices'}), 500

@device_bp.route('/<int:device_id>', methods=['PUT'])
@jwt_required()
def update_device(device_id):
    """Update device information"""
    try:
        user_id = get_jwt_identity()
        user = User.query.get(user_id)
        
        if not user or not user.patient_profile:
            return jsonify({'error': 'Patient profile not found'}), 404
        
        device = Device.query.filter_by(
            id=device_id, 
            patient_id=user.patient_profile.id
        ).first()
        
        if not device:
            return jsonify({'error': 'Device not found'}), 404
        
        data = request.get_json()
        
        # Update device fields
        if 'device_name' in data:
            device.device_name = data['device_name'].strip()
        if 'manufacturer' in data:
            device.manufacturer = data['manufacturer'].strip() or None
        if 'model' in data:
            device.model = data['model'].strip() or None
        if 'firmware_version' in data:
            device.firmware_version = data['firmware_version'].strip() or None
        if 'is_active' in data:
            device.is_active = bool(data['is_active'])
        
        db.session.commit()
        
        return jsonify({
            'message': 'Device updated successfully',
            'device': {
                'id': device.id,
                'device_name': device.device_name,
                'device_type': device.device_type.value,
                'is_active': device.is_active
            }
        }), 200
        
    except Exception as e:
        db.session.rollback()
        current_app.logger.error(f'Update device error: {str(e)}')
        return jsonify({'error': 'Failed to update device'}), 500

@device_bp.route('/<int:device_id>/sync', methods=['POST'])
@jwt_required()
def sync_device_data():
    """Sync data from device"""
    try:
        user_id = get_jwt_identity()
        user = User.query.get(user_id)
        
        if not user or not user.patient_profile:
            return jsonify({'error': 'Patient profile not found'}), 404
        
        device_id = request.view_args['device_id']
        device = Device.query.filter_by(
            id=device_id, 
            patient_id=user.patient_profile.id
        ).first()
        
        if not device:
            return jsonify({'error': 'Device not found'}), 404
        
        if not device.is_active:
            return jsonify({'error': 'Device is not active'}), 400
        
        data = request.get_json()
        sync_method = data.get('method', 'manual')  # manual, bluetooth, api
        
        synced_records = []
        
        if sync_method == 'bluetooth':
            # Bluetooth sync
            bt_handler = BluetoothDeviceHandler()
            try:
                device_data = bt_handler.sync_device(device.device_id, device.device_type.value)
                synced_records = process_device_data(device, device_data)
            except Exception as e:
                current_app.logger.error(f'Bluetooth sync error: {str(e)}')
                return jsonify({'error': 'Bluetooth sync failed'}), 500
                
        elif sync_method == 'api':
            # API sync
            api_handler = DeviceAPIHandler()
            try:
                device_data = api_handler.sync_device(device.device_id, device.device_type.value)
                synced_records = process_device_data(device, device_data)
            except Exception as e:
                current_app.logger.error(f'API sync error: {str(e)}')
                return jsonify({'error': 'API sync failed'}), 500
                
        elif sync_method == 'manual' and 'data' in data:
            # Manual data entry
            synced_records = process_device_data(device, [data['data']])
        
        # Update device last sync time
        device.last_sync = datetime.utcnow()
        db.session.commit()
        
        return jsonify({
            'message': 'Device synced successfully',
            'synced_records': len(synced_records),
            'records': synced_records
        }), 200
        
    except Exception as e:
        db.session.rollback()
        current_app.logger.error(f'Device sync error: {str(e)}')
        return jsonify({'error': 'Device sync failed'}), 500

@device_bp.route('/scan', methods=['POST'])
@jwt_required()
def scan_bluetooth_devices():
    """Scan for available Bluetooth devices"""
    try:
        user_id = get_jwt_identity()
        user = User.query.get(user_id)
        
        if not user:
            return jsonify({'error': 'User not found'}), 404
        
        bt_handler = BluetoothDeviceHandler()
        
        # Get scan timeout from request or use default
        data = request.get_json() or {}
        timeout = data.get('timeout', current_app.config.get('BLUETOOTH_SCAN_TIMEOUT', 10))
        
        try:
            devices = bt_handler.scan_devices(timeout)
            return jsonify({
                'message': 'Bluetooth scan completed',
                'devices': devices
            }), 200
        except Exception as e:
            current_app.logger.error(f'Bluetooth scan error: {str(e)}')
            return jsonify({'error': 'Bluetooth scan failed'}), 500
        
    except Exception as e:
        current_app.logger.error(f'Scan devices error: {str(e)}')
        return jsonify({'error': 'Failed to scan devices'}), 500

@device_bp.route('/<int:device_id>/test', methods=['POST'])
@jwt_required()
def test_device_connection():
    """Test device connection"""
    try:
        user_id = get_jwt_identity()
        user = User.query.get(user_id)
        
        if not user or not user.patient_profile:
            return jsonify({'error': 'Patient profile not found'}), 404
        
        device_id = request.view_args['device_id']
        device = Device.query.filter_by(
            id=device_id, 
            patient_id=user.patient_profile.id
        ).first()
        
        if not device:
            return jsonify({'error': 'Device not found'}), 404
        
        # Test connection based on device type
        connection_result = {
            'device_id': device.device_id,
            'device_type': device.device_type.value,
            'connection_status': 'testing'
        }
        
        try:
            # Try Bluetooth connection first
            bt_handler = BluetoothDeviceHandler()
            if bt_handler.test_connection(device.device_id):
                connection_result.update({
                    'connection_status': 'connected',
                    'connection_type': 'bluetooth',
                    'signal_strength': bt_handler.get_signal_strength(device.device_id)
                })
            else:
                # Try API connection
                api_handler = DeviceAPIHandler()
                if api_handler.test_connection(device.device_id):
                    connection_result.update({
                        'connection_status': 'connected',
                        'connection_type': 'api'
                    })
                else:
                    connection_result['connection_status'] = 'disconnected'
                    
        except Exception as e:
            current_app.logger.error(f'Device test error: {str(e)}')
            connection_result['connection_status'] = 'error'
            connection_result['error'] = str(e)
        
        return jsonify({
            'message': 'Device connection test completed',
            'result': connection_result
        }), 200
        
    except Exception as e:
        current_app.logger.error(f'Test device error: {str(e)}')
        return jsonify({'error': 'Device test failed'}), 500

def process_device_data(device, data_list):
    """Process and validate device data"""
    synced_records = []
    
    for data_item in data_list:
        try:
            # Validate data format
            validation_result = validate_health_data(device.device_type.value, data_item)
            if not validation_result['valid']:
                current_app.logger.warning(f'Invalid data from device {device.device_id}: {validation_result["errors"]}')
                continue
            
            # Create health record
            health_record = HealthRecord(
                patient_id=device.patient_id,
                device_id=device.id,
                record_type=device.device_type.value,
                value=data_item.get('value'),
                unit=data_item.get('unit'),
                timestamp=datetime.fromisoformat(data_item['timestamp']) if 'timestamp' in data_item else datetime.utcnow(),
                notes=data_item.get('notes')
            )
            
            db.session.add(health_record)
            synced_records.append({
                'record_type': health_record.record_type,
                'value': health_record.value,
                'unit': health_record.unit,
                'timestamp': health_record.timestamp.isoformat()
            })
            
        except Exception as e:
            current_app.logger.error(f'Error processing device data: {str(e)}')
            continue
    
    return synced_records
