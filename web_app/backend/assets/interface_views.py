from django.core.exceptions import ValidationError as DjangoValidationError
from django.core.paginator import Paginator
from django.db import IntegrityError, transaction
from django.db.models import CharField, Count, Exists, OuterRef, Prefetch, Q
from django.db.models.functions import Cast
from django.shortcuts import get_object_or_404

from rest_framework import status
from rest_framework.exceptions import ValidationError
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView

from ingestion.models import Ingestion, InterfaceObservation

from .interface_permissions import NetworkInterfacePermission
from .interface_assignment import (
    identify_interface, unlink_interface, create_identified_interface,
)
from .interface_serializers import (
    InterfaceObservationDetailSerializer,
    NetworkInterfaceCreateSerializer,
    NetworkInterfaceReadSerializer,
)
from .models import Asset, Hardware, NetworkInterface
from .permissions import AssetArchivePermission
from .serializers import InterfaceAssignmentSerializer


PAGE_SIZE = 25


def interface_queryset():
    active_evidence = InterfaceObservation.objects.filter(
        network_interface_id=OuterRef("pk"),
        ingestion__status=Ingestion.Status.ACTIVE,
    )

    observation_query = InterfaceObservation.objects.select_related(
        "ingestion"
    ).order_by("id")

    return (
        NetworkInterface.objects
        .select_related("hardware__asset", "created_by", "identified_by")
        .annotate(
            observation_count=Count("observations", distinct=True),
            active_observation_count=Count(
                "observations",
                filter=Q(observations__ingestion__status=Ingestion.Status.ACTIVE),
                distinct=True,
            ),
            has_active_evidence=Exists(active_evidence),
        )
        .prefetch_related(
            Prefetch("observations", queryset=observation_query,
                     to_attr="prefetched_observations")
        )
    )


def positive_page(request):
    raw = request.query_params.get("page", "1")
    try:
        page = int(raw)
    except (ValueError, TypeError) as error:
        raise ValidationError({"page": "Debe ser un número entero."}) from error
    if page < 1:
        raise ValidationError({"page": "Debe ser mayor que cero."})
    return page


class InterfaceListCreateView(APIView):
    permission_classes = [IsAuthenticated, NetworkInterfacePermission]

    def get(self, request):
        page = positive_page(request)
        search = request.query_params.get("search", "").strip()[:100]
        identification = request.query_params.get("identification", "ALL")
        evidence = request.query_params.get("evidence", "ALL")
        hardware_id = request.query_params.get("hardware_id")

        if identification not in ("ALL", "IDENTIFIED", "UNIDENTIFIED"):
            raise ValidationError({
                "identification": "Usa ALL, IDENTIFIED o UNIDENTIFIED."
            })
        if evidence not in ("ALL", "ACTIVE", "NO_ACTIVE"):
            raise ValidationError({
                "evidence": "Usa ALL, ACTIVE o NO_ACTIVE."
            })

        queryset = interface_queryset()

        if hardware_id is not None:
            try:
                hw_id = int(hardware_id)
                if hw_id <= 0:
                    raise ValueError()
            except (ValueError, TypeError) as error:
                raise ValidationError({"hardware_id": "Indica un ID positivo."}) from error
            queryset = queryset.filter(hardware_id=hw_id)

        if identification == "IDENTIFIED":
            queryset = queryset.filter(hardware__isnull=False)
        elif identification == "UNIDENTIFIED":
            queryset = queryset.filter(hardware__isnull=True)

        if evidence == "ACTIVE":
            queryset = queryset.filter(has_active_evidence=True)
        elif evidence == "NO_ACTIVE":
            queryset = queryset.filter(has_active_evidence=False)

        if search:
            observed_ip_match = (
                InterfaceObservation.objects
                .filter(network_interface_id=OuterRef("pk"))
                .annotate(ips_as_text=Cast("ips", output_field=CharField()))
                .filter(ips_as_text__icontains=search)
            )
            queryset = (
                queryset
                .annotate(
                    declared_ip_text=Cast("declared_ip", output_field=CharField()),
                    matches_observed_ip=Exists(observed_ip_match),
                )
                .filter(
                    Q(mac__icontains=search)
                    | Q(declared_ip_text__icontains=search)
                    | Q(matches_observed_ip=True)
                )
            )

        paginator = Paginator(queryset.order_by("id"), PAGE_SIZE)
        selected = paginator.get_page(page)

        summary = NetworkInterface.objects.aggregate(
            total=Count("id"),
            identified=Count("id", filter=Q(hardware__isnull=False)),
            unidentified=Count("id", filter=Q(hardware__isnull=True)),
        )
        return Response({
            "summary": summary,
            "count": paginator.count,
            "page": selected.number,
            "page_size": PAGE_SIZE,
            "results": NetworkInterfaceReadSerializer(
                selected.object_list, many=True
            ).data,
        })

    def post(self, request):
        serializer = NetworkInterfaceCreateSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        try:
            with transaction.atomic():
                interface = NetworkInterface(
                    **serializer.validated_data,
                    created_by=request.user,
                )
                interface.save()
        except DjangoValidationError as error:
            details = (
                error.message_dict if hasattr(error, "message_dict")
                else {"non_field_errors": error.messages}
            )
            raise ValidationError(details) from error
        except IntegrityError as error:
            raise ValidationError({
                "mac": "La MAC ya existe o incumple una restricción."
            }) from error

        interface = get_object_or_404(interface_queryset(), pk=interface.pk)
        return Response(
            NetworkInterfaceReadSerializer(interface).data,
            status=status.HTTP_201_CREATED,
        )


class InterfaceDetailView(APIView):
    permission_classes = [IsAuthenticated, NetworkInterfacePermission]

    def get(self, request, interface_id):
        page = positive_page(request)
        interface = get_object_or_404(interface_queryset(), pk=interface_id)

        observations = (
            InterfaceObservation.objects
            .filter(network_interface=interface)
            .select_related("ingestion")
            .order_by("id")
        )
        paginator = Paginator(observations, PAGE_SIZE)
        selected = paginator.get_page(page)

        payload = NetworkInterfaceReadSerializer(interface).data
        payload["observations"] = {
            "count": paginator.count,
            "page": selected.number,
            "page_size": PAGE_SIZE,
            "results": InterfaceObservationDetailSerializer(
                selected.object_list, many=True
            ).data,
        }
        return Response(payload)



class InterfaceIdentifyView(APIView):
    permission_classes = [IsAuthenticated, NetworkInterfacePermission]

    def post(self, request, interface_id):
        if set(request.data.keys()) != {"asset_id"}:
            raise ValidationError({"asset_id": "Envía únicamente asset_id."})
        try:
            asset_id = int(request.data["asset_id"])
            if asset_id <= 0:
                raise ValueError()
        except (TypeError, ValueError) as error:
            raise ValidationError({"asset_id": "Debe ser un entero positivo."}) from error
        updated = identify_interface(
            interface_id=interface_id, asset_id=asset_id, user=request.user,
        )
        return Response(NetworkInterfaceReadSerializer(
            get_object_or_404(interface_queryset(), pk=updated.pk)
        ).data)


class InterfaceUnlinkView(APIView):
    permission_classes = [IsAuthenticated, NetworkInterfacePermission]

    def post(self, request, interface_id):
        if request.data:
            raise ValidationError({"detail": "No se esperan datos."})
        updated = unlink_interface(interface_id=interface_id)
        return Response(NetworkInterfaceReadSerializer(
            get_object_or_404(interface_queryset(), pk=updated.pk)
        ).data)



class AssetInterfaceAssignView(APIView):
    """Register or associate a network interface on an existing hardware asset."""

    permission_classes = [IsAuthenticated, AssetArchivePermission]

    def post(self, request, asset_id):
        serializer = InterfaceAssignmentSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        assignment = serializer.validated_data

        with transaction.atomic():
            if assignment["mode"] == "EXISTING":
                interface = identify_interface(
                    interface_id=assignment["interface_id"],
                    asset_id=asset_id, user=request.user,
                )
            else:
                asset = get_object_or_404(
                    Asset.objects.select_for_update(), pk=asset_id
                )
                from .interface_assignment import validate_hardware_asset
                validate_hardware_asset(asset)
                hardware = get_object_or_404(Hardware, pk=asset.pk)
                interface = create_identified_interface(
                    hardware=hardware,
                    mac=assignment.get("mac"),
                    declared_ip=assignment.get("declared_ip"),
                    user=request.user,
                )

        loaded = get_object_or_404(interface_queryset(), pk=interface.pk)
        return Response(
            NetworkInterfaceReadSerializer(loaded).data,
            status=status.HTTP_201_CREATED if assignment["mode"] == "MANUAL"
            else status.HTTP_200_OK,
        )
