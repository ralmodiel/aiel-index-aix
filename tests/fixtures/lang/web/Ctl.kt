package app
import org.springframework.web.bind.annotation.*
@RestController
@RequestMapping("/orders")
class OrderController(private val svc: OrderService) {
    @GetMapping("/{id}")
    fun get(@PathVariable id: Long) = svc.find(id)
    @PreAuthorize("hasRole('ADMIN')")
    @PostMapping
    fun create(@RequestBody o: Order) = svc.save(o)
}
